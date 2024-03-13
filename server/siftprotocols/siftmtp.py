#python3

import sys, getopt, getpass
import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 1
		self.version_minor = 0
		self.msg_hdr_ver = b'\x01\x00'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.size_msg_hdr_rsv = 2
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket
		self.final_key = bytes()
		self.msg_sqn = 1
		self.last_receieved_sqn = 0

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'], i = msg_hdr[i:i+self.size_msg_hdr_rsv], i+self.size_msg_hdr_rsv
		return parsed_msg_hdr


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# receives n bytes from the peer socket
	def receive_bytes(self, n):
		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received


	# builds and sends message of a given type using the provided payload
	# (only used after login protocol)
	def send_msg(self, msg_type, msg_payload):
		
		# initializing values for message header
		msg_hdr_sqn = self.msg_sqn.to_bytes(length=2, byteorder='big')
		msg_hdr_rnd = Random.get_random_bytes(6)
		msg_hdr_rsv = b'\x00\x00'

		# build message
		msg_size = self.size_msg_hdr + len(msg_payload) + 12
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_hdr_sqn + msg_hdr_rnd + msg_hdr_rsv

		# encrypting the message with AES in GCM mode
		nonce = msg_hdr_sqn + msg_hdr_rnd
		authtag_length = 12
		AE = AES.new(self.final_key, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
		AE.update(msg_hdr)
		encrypted_payload, authtag = AE.encrypt_and_digest(msg_payload)

		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('EPD (' + str(len(encrypted_payload)) + '): ')
			print(encrypted_payload.hex())
			print('MAC (' + str(len(authtag)) + '): ')
			print(authtag.hex())
			print('------------------------------------------')
		# DEBUG 

		# try to send
		try:
			self.send_bytes(msg_hdr + encrypted_payload + authtag)
			self.msg_sqn += 1
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)


	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):

		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')
		
		if parsed_msg_hdr['sqn'] <= self.last_receieved_sqn.to_bytes(length=2, byteorder='big'):
			raise SiFT_MTP_Error('Message SQN number is <= the last received SQN number')

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		try:
			encrypted_payload = self.receive_bytes(msg_len - (self.size_msg_hdr + 12))
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)
		
		try:
			authtag = self.receive_bytes(12)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)
		
		# decrypting the encrypted payload with the temp_key
		print("Decryption and authentication tag verification is attempted...")
		nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
		AE = AES.new(self.final_key, AES.MODE_GCM, nonce=nonce, mac_len=12)
		AE.update(msg_hdr)
		try:
				payload = AE.decrypt_and_verify(encrypted_payload, authtag)
		except Exception as e:
				print("Error: Operation failed!")
				print("Processing completed.")
				sys.exit(1)
		print("Operation was successful: message is intact, content is decrypted.")

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(encrypted_payload)) + '): ')
			print(encrypted_payload.hex())
			print('MAC (' + str(len(authtag)) + '): ')
			print(authtag.hex())
			print('------------------------------------------')
		# DEBUG 

		if len(payload) != msg_len - (self.size_msg_hdr + 12): 
			raise SiFT_MTP_Error('Incomplete message body reveived')

		self.last_receieved_sqn += 1

		return parsed_msg_hdr['typ'], payload
	

	# receives and parses message, returns msg_type and msg_payload
	def receive_login_req(self):
		print("Receiving login req from client ...")
		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')
		
		if parsed_msg_hdr['sqn'] != b'\x00\x01':
			raise SiFT_MTP_Error('Login Request SQN number is not 1')

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		try:
			encrypted_payload = self.receive_bytes(msg_len - (self.size_msg_hdr + 12 + 256))
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)
		
		try:
			authtag = self.receive_bytes(12)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)
		
		try:
			encrypted_temp_key = self.receive_bytes(256)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		# loads the server's private key to decrypt the temporary key of the login req
		def load_keypair(privkeyfile):
			passphrase = "crysys"
			with open(privkeyfile, 'rb') as f:
					keypairstr = f.read()
			try:
					return RSA.import_key(keypairstr, passphrase=passphrase)
			except ValueError:
					print('Error: Cannot import private key from file ' + privkeyfile)
					sys.exit(1)

		keypair = load_keypair('siftprotocols/server_privkey.pem')

		RSAcipher = PKCS1_OAEP.new(keypair)

		temp_key = RSAcipher.decrypt(encrypted_temp_key)

		# decrypting the encrypted payload with the temp_key
		nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
		AE = AES.new(temp_key, AES.MODE_GCM, nonce=nonce, mac_len=12)
		AE.update(msg_hdr)
		try:
				payload = AE.decrypt_and_verify(encrypted_payload, authtag)
		except Exception as e:
				print("Error: Decrypting the login request failed!")
				print("Processing completed.")
				sys.exit(1)
		print("Operation was successful: message is intact, content is decrypted.")

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('EPD (' + str(len(encrypted_payload)) + '): ')
			print(encrypted_payload.hex())
			print('MAC (' + str(len(authtag)) + '): ')
			print(authtag.hex())
			print('ETK (' + str(len(encrypted_temp_key)) + '): ')
			print(encrypted_temp_key.hex())
			print('------------------------------------------')
		# DEBUG 

		if len(encrypted_payload) != msg_len - (self.size_msg_hdr + 12 + 256): 
			raise SiFT_MTP_Error('Incomplete message body reveived')
		
		self.last_receieved_sqn += 1

		return parsed_msg_hdr['typ'], payload, temp_key


	# builds the login res with the provided information from the server
	def send_login_res(self, msg_type, msg_payload, key):
		print("Sending login response ...")

		# initailizing values for login response
		msg_hdr_sqn = self.msg_sqn.to_bytes(length=2, byteorder='big')
		msg_hdr_rnd = Random.get_random_bytes(6)
		msg_hdr_rsv = b'\x00\x00'

		# build message
		msg_size = self.size_msg_hdr + len(msg_payload) + 12
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_hdr_sqn + msg_hdr_rnd + msg_hdr_rsv

		# encrypt message using AES in GCM mode
		nonce = msg_hdr_sqn + msg_hdr_rnd
		authtag_length = 12
		AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
		AE.update(msg_hdr)
		encrypted_payload, authtag = AE.encrypt_and_digest(msg_payload)

		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('EPD (' + str(len(encrypted_payload)) + '): ')
			print(encrypted_payload.hex())
			print('MAC (' + str(len(authtag)) + '): ')
			print(authtag.hex())
			print('------------------------------------------')

		# try to send
		try:
			self.send_bytes(msg_hdr + encrypted_payload + authtag)
			self.msg_sqn += 1
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

		
	# sets the final_key to the key derived from the login protocol
	def set_key(self, key):
		self.final_key = key

