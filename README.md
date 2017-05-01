# Programming Assignment 5
### Gannon Faul
### 04/30/17
### CSCI 3753

#### To build code:

1. Navigate to directory with all the files in it.
2. Type `make` and hit enter.
3. Type `./pa5-encfs <key> <mirrored directory> <mount point>` and it enter
4. Make/edit files in the mount point, and they will be encrypted in the mirrored directory

#### When finished:

1. Navigate to directory with all the files in it.
2. Type `fusermout -u <mount point>` and hit enter.
3. Mount point is now removed, and the files in the mirrored directory are safely encrypted.


#### Example: 

1. `make`
2. `./pa5-encfs hello /home/user/Desktop/test /home/user/Desktop/pa5/test1`
3. `echo "This file will be encrypted" > /home/user/Desktop/pa5/test1/encrypt.txt`
4. `cat /home/user/Desktop/pa5/test1/encrypt.txt` (Will output "This file will be encrypted").
5. `cat /home/user/Desktop/test/encrypt.txt` (Will output encrypted text).

#### To test encryption/xattr functionality:

1. Follow the example steps above.
2. `echo "Unencrypted File" > /home/user/Desktop/test/plain.txt`
3. `./aes-crypt-util -d hello /home/user/Desktop/test/encrypt.txt /home/user/Desktop/test/encrypt1.txt`
4. `cat /home/user/Desktop/test/encrypt1.txt` (Will output "This file will be encrypted").
5. `./xattr-util -l /home/user/Desktop/pa5/test1/encrypt.txt` (Will list xattr "user.pa5-encfs.encrypted").
6. `./xattr-util -l /home/user/Desktop/pa5/test1/plain.txt` (Will list no xattr because none is set).