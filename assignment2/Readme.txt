Please have a look at the readme.txt before trying to execute all the code:

Part 1: Asymmetric Encryption
- When executing part 1 in terminal, you will need to enter 2 arguments in the terminal. The first terminal will determine the length of the RSA key, be default you can enter 2048.
Second argument will be the order of encryption/decryption process. In both terminal of server and client you will need to enter the order (since the handout doesn't say only client/
server can enter the order), if the order between both server and client does not match, the program will not run)
- Plain text after encrypted by both server and client will be print out in the console. I've also added comments in the console to show when the server is running.

Part 2: Key Management
- The key store has already been provided in the zip file, I've looked at the instruction file provided, I've seen that we also need to provide cybr372.jks so that's the reason why.
- You can change the password within the program by enter "change" in the first argument in both server side/ client side, again this is becasue the handout does not specify only
server/client can change the password. The first argument is Ignorecase,so you can enter "change"/"CHANGE", it will still work. The default password will be badpassword(try password
if badpassword gives you error).
- If you don't wish to perform password changing then you can run part 2 in the same way as part 1. The first argument is keylength and the second argument in order of encryption/
decryption process. Again, in both server side and client side, you will need to enter the order of encryption/decryption process.

Part 3: Secure Channel
- For this part, the only argument you need to enter is the number of messages using the same secret key before a new session key must be chosen.
- The comment in the console will show you that how many times we can use the same key before a new key must be chosen
- A mechanism to prevent reply attacks has also been provided which is using NONCE. The decryption will only work after the checking NONCE takes place. If the program finds out that
NONCE has been used before, the program will immediately crash.
- Keystore is still provided since we need to used asymmetric cryptography for key negotiation, asymmetric keys for key negotiation is stored inside the keystore.
- You will not be able to change the password since part 3 doesn't require that action to be performed.
- If you've encounter connection refuse, please wait a little bit and re-try again. I've tried everything to solve the problem, but sometimes it still occurs, sorry about that.