🏷️ Encrypted NFC Backup 🔒
A lightweight app to encrypt my crypto wallet so I could backups securely on NFC cards. No cloud, no USB drives, just encrypt any text and use my phone to write tha hash to an NFC tag.
I created this for personal use, but maybe others could benefit too. It's not limited to crypto bros and degens.
Use NTAG213/215/216 cards for higher compatibility. Your phone may or may can't write any newer tags.

Features:
 - Encrypt a text with eas256-gcm, derivating the key from a password you give
 - Password strength indicator
 - Generating QR code from the encrypted data (easy transfer to phone, to write the NFC tag)
 - Decrypt your data from hash or QR code, using your password (if password is correct)
