'''
 *  Copyright (C) 2015 Cisco Talos Security Intelligence and Research Group
 *
 *  Authors: Emmanuel Tacheau and Andrea Allievi
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 * 
 *	Filename: TeslaDeCrypt.py
 *	This module will perform AES decryption for file encrypted with
 *      the ransomware TeslaCrypt
 *
 *      Usage:   python TeslaDecrypt.py --file file_encrypted.ecc --key master_key
 *               The result will produce a file named file_encrypted.dec using AES 256 CBC mode
 *
 *               Encrypted files are defined as follow:
 *               First 16 bytes are containing IV
 *               Then with 4 bytes is the length of the file
 *               Then the encrypted data
 *
 *	Last revision: 04/17/2015
 *
'''
import os

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
except ImportError:
    print 'You must have pycrypto module installed'
    exit

try:
        import argparse
    except ImportError:
        print 'You have to install argparse python module'
        exit

    import sys
    import binascii
    from textwrap import dedent

def main():
    print("TeslaCrypt Decryption Tool 0.2")
    #print("Emmanuel Tacheau and Andrea Allievi")
    print("Copyright (C) 2015 Talos Security Intelligence and Research Group")
    print("Cisco Systems Inc.\n")
    

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                            epilog=dedent('''
                                Running for example :
                                \npython TeslaDecrypt.py --fic abc.py.ecc --decrypt --key 04684d9d06102effe5cadd3b218d61e37a4c693b995a6cb76db2978a2dbfd2e2
                                should produce output like "Wrote decrypted file abc.py.ecc.dec" where aby.py.ecc.dec is the decrypted file
                                '''))
    parser.add_argument('--fic',
                        type=argparse.FileType('rb'),
                        help='Specify binary file to crypt or decrypt details')
    parser.add_argument('--decrypt',
                        action='store_true',
                        help='perform a decryption operation')
    parser.add_argument('--encrypt',
                        action='store_true',
                        help='perform an encryption operation')
    parser.add_argument('--test_mode',
                        action='store_true',
                        help='Test mode internal testing')
    parser.add_argument('--key',
                        default=None,
                        help='Specify a key string to use as key encryption')
    parser.add_argument('--keyfile', default=None, 
                        type=argparse.FileType('rb'),
                        help='Specify the \'key.dat\' file to be used to retrieve the master key')
    parser.add_argument('--iv',
                        default=None,
                        help='Specify IV value to be used')
    parser.add_argument('--mode',
                        choices=[AES.MODE_ECB,AES.MODE_CBC,AES.MODE_CFB],
                        default=AES.MODE_CBC,
                        help='Encryption mode to be used with MODE_ECB=1, MODE_CBC=2,MODE_CFB=3')

    args=parser.parse_args()
    checks=False
    cipher_key=None
    iv_key=None

	# E.T - 05/04/2015 
	# Fixed: cipher_key must be a binary data
    if args.key:
        cipher_key= binascii.unhexlify(args.key)

    encrypted=None
    cleardata=None


    # Get if I need to recover the key from the 'key.dat' file
    if (args.keyfile != None):
        # TeslaCrypt 3 Key file:
        #      
        # PART 1:
        # + 0x00 - Base58 string of OS data used as Payment ID (size 0x28 - calculated @ 00401F60)
        #
        # PART 2:
        # + 0x64 - 0x20 bytes of a SHA1 key derived from the OS info (calculated @ 41B400)
        # + 0x84 - 0x20 bytes of a SHA1 key derived from the OS info 
        # + 0xA4 - 0x40 bytes of a SHA1 key array derived from the OS info 
        # + 0xE5 - 0x40 bytes of a SHA1 key array derived from the OS info
        #
        # PART 3:
        # + 0x136 - Shifted Payment Key (size 0x20)
        # + 0x177 - Shifted Master key (size 0x20)

        # Open the target 'key.dat' file
        keybuff = args.keyfile.read()
        args.keyfile.close()
        shifted_key = keybuff[0x177:0x197]
        sha256 = SHA256.SHA256Hash(shifted_key)
        # Get the Chiper key
        cipher_key = sha256.digest();

    if args.fic:
        # If we're in decryption mode
        if args.decrypt:
            try:
                dataencrypted = args.fic.read()
                args.fic.close()
            except IOError:
                print >> sys.stderr, "Error in opening file"
                return
            except Exception, e:
                print >> sys.stderr, "does not exist"
                print >> sys.stderr, "Exception: %s" % str(e)
                return
            # encrypted data is using the following format
            # first 16 bytes are containing IV
            # then next 4 bytes are containing file length
            # finally rest of file is containing encrypted data
            # Noticed: Bytes are 2 hex digits, so number are * by 2
            if dataencrypted and cipher_key:
                iv_key=dataencrypted[:16]
                size_str = dataencrypted[16:20]
                # Convert size str in an integer
                size = int(size_str[::-1].encode('hex'), 16)
                cipherdata=dataencrypted[20:]
                try:
                    context = AES.new(cipher_key, args.mode, iv_key)
                    cleardata = context.decrypt(cipherdata)
                except Exception,e:
                    print >> sys.stderr, "Error in crypto handling"
                    print >> sys.stderr, "Exception: %s" % str(e)
                    return

            if cleardata:
                try:
                    output_tuple = os.path.splitext(args.fic.name)
                    if (output_tuple[1] == '.ecc'):
                        output_tuple = os.path.splitext(output_tuple[0])
                    output_filename = output_tuple[0] + "_decrypted" + output_tuple[1]
                    fdesc = open(output_filename,'wb')
                    # Write only the actual real data
                    fdesc.write(cleardata[:size])
                    fdesc.close()
                    print 'Wrote decrypted file', output_filename
                except IOError:
                    print >> sys.stderr, "Error in writing file"
                    return
                except Exception, e:
                    print >> sys.stderr, "does not exist"
                    print >> sys.stderr, "Exception: %s" % str(e)
                    return

    elif args.test_mode:
        cleardata='7710e1f4ea97a37c48f64e26caca7b78'
        iv_key='94835a59f4eff3019a5ba8a53aef6940'
        cipher_key='04684d9d06102effe5cadd3b218d61e37a4c693b995a6cb76db2978a2dbfd2e2'
        print 'clear data:',cleardata
        context=AES.new(binascii.unhexlify(cipher_key),args.mode,binascii.unhexlify(iv_key))
        cipherdata=binascii.hexlify(context.encrypt(binascii.unhexlify(cleardata)))
        print 'cipher_data:',cipherdata
        new_iv = cipherdata
        todecrypt=iv_key
        context=AES.new(binascii.unhexlify(cipher_key),args.mode,binascii.unhexlify(iv_key))
        new_clear_data=binascii.hexlify(context.decrypt(binascii.unhexlify(cipherdata)))
        print 'decrypted :',new_clear_data

    else:
        print("Command line error!")
        parser.print_help()

if __name__ == '__main__':
  main()
