🏷️ Encrypted NFC Backup 🔒

A lightweight app to encrypt my crypto wallet so I could backups securely on NFC cards. No cloud, no USB drives, just encrypt any text and use my phone to write the hash to an NFC tag.

I created this for personal use (and for some close friends), but maybe others could benefit too. It's not limited to crypto bros and degens. As it can create QR code, you can encrypt anything, take a screenshot or print the QR code.

Use NTAG213/215/216 cards for higher compatibility. Your phone may or may can't write any newer tags.

Features (web):
 - Encrypt a text with eas256-gcm, derivating the key from a password you give
 - Password strength indicator
 - Generating QR code from the encrypted data (easy transfer to phone, to write the NFC tag)
 - Decrypt your data from hash or QR code, using your password (if password is correct)

CLI:
 - Why would anyone trust a scammy websie/app? Providing cli scripts and apps to do this yourself on your own machine, even without internet...


Demo: https://nfceed.angelhost.eu/
