# iModel

This is a project written in Java, corresponding to our local simulations of the Semi-$\mathsf{iModel}$ and Full-$\mathsf{iModel}$ constructions. The project includes specific algorithms for both constructions, which can be called and used.

## Functionality

Our solution implements cloud-based hierarchical management of AI models. The Semi-$\mathsf{iModel}$ and Full-$\mathsf{iModel}$ architectures respectively achieve hierarchical management of AI models in two scenarios: a semi-dependent scenario where AI providers participate in model management, and a fully-dependent multi-cloud collaboration scenario that eliminates the need for AI provider involvement.

## Project Structure

- a.properties: Elliptic curve parameter file.

- Full_iModel.java: Class defining Full-$\mathsf{iModel}$ and its algorithms.

- Paillier.java: An open-source implementation of the Paillier homomorphic encryption algorithm.

- Semi_iModel.java: Class defining Semi-$\mathsf{iModel}$ and its algorithms.

## Runtime Environment

We conducted experiments locally on a 64-bit laptop running on a Windows 10 system with 8GB of memory, and the processor is Intel® Core™ i5-8250U CPU @ 1.60GHz 1.80 GHz. We used Java with JDK-14 and relied on version 2.0.0 of the JPBC library, which can be downloaded and installed from [http://gas.dia.unisa.it/projects/jpbc/download.html]().

## Detailed Function Introduction

### Semi_iModel.java

`H1()`: A private function called by other functions to compute the SHA256 hash. The input is data of type `byte[]`, and it returns an element in $\mathbb{Z}_p$.

`H2()`: A private function called by other functions to compute the SHA256 hash. The input is an element in $G_T$, and it returns data of type `byte[]`.

`generateVid()`: A private function called by other functions to generate a 256-bit pseudonymous account.

`setUp()`: Called by the KGC to implement the **Setup** process. The inputs are the total user number and model size, and it returns the master secret key and master public key.

`keyGen()`: Called by the KGC to implement the **KeyGen** process. The inputs are the master secret key and user account, and it returns the generated $r_{id}, sk_{id}, v_{id}$.

`calculatePolyCoefficients()`: A private function called by other functions to compute polynomial coefficients. The inputs are the permission control policy and a random number, and it returns a polynomial coefficient array.

`calculateH1c0()`: A private function called by other functions to compute the value of $H_1(c_0)$.

`xorBytes()`: A private function called by other functions to perform an XOR operation on two `byte[]` type data. If the hash is longer, it will be truncated to the length of the bytes before XORing. If the bytes are longer, the hash will be looped before XORing.

`modToBytes()`: A private function called by other functions to convert a model parameter list into `byte[]` type data.

`bytesToMod()`: A private function called by other functions to parse `byte[]` type data into model parameters.

`paillierEncrypt()`: A public algorithm for Paillier homomorphic encryption. The inputs are the Paillier public key and a Biginteger type message, and it returns a Biginteger type ciphertext.

`paillierDecrypt()`: A public algorithm for Paillier decryption. The inputs are the Paillier public key, Paillier secret key, and a Biginteger type ciphertext, and it returns the decrypted result as a Biginteger.

`modProcess()`: Called by the AI provider to implement the **ModProcess** process. The inputs are the model parameter array, permission control policy, master public key, and Paillier public key, and it returns the chameleon hash result and processed model.

`intCheck()`: A public algorithm to implement the **ModProcess** process. The inputs are the chameleon hash and processed model, and it returns true/false.

`riToken()`: Called by the AI user to implement the **RiToken** process. The inputs are the request type and user secret key, and it returns the result $(Req, T_{id})$.

`riCheck()`: Called by the cloud server to implement the **RiCheck** process. The inputs are the request type, processed model, user’s right token, and pseudonymous account, and it returns a flag. If the verification is successful, the corresponding $p_1$/$p_2$/$p_3$ will also be returned.

`modAvail_AIUserSide()`: Called by an AI user with Avail permission to implement the AI user side of the **ModAvail** process. The inputs are the user secret key, $p_1$ obtained from the cloud server, and the user plaintext message, and it returns the encrypted data.

`modAvail_CloudServerSide()`: Called by the cloud server to implement the cloud server side of the **ModAvail** process. The inputs are the user-submitted ciphertext and processed model, and it outputs the ciphertext of the model execution result. To call this function, the actual model must be invoked within this function.

`modAvail_AIProviderSide()`: Called by the AI provider to implement the AI provider side of the **ModAvail** process. The inputs are the Paillier public key, Paillier secret key, and the ciphertext of the model execution result, and it outputs the decrypted model execution result.

`modTrain()`: Called by an AI user with Train permission. The inputs are the user secret key and $p_2$ obtained from the cloud server, and it returns the processed local model. To call this function, the actual model must be invoked within this function.

`modUpgrade()`: Called by an AI user with Upgrade permission. The inputs are the user secret key, $p_1, p_2, p_3$ obtained from the cloud server, and the list of collected local models $C_{M,2}$, and it returns the new processed global model.

`CM3replaceCM1()`: A private function called by other functions to replace the corresponding parameters in $C_{M,1}$ with those in $C_{M,3}$.

### Full_iModel.java

Similar to the functions in Semi_iModel.java, with the following differences:

`pkhsToBytes()`: A private function called by other functions. Converts Paillier public keys into `byte[]` type data.

`parsePkhs()`: A private function called by other functions. Parses `byte[]` type data into Paillier public keys.

`modProcess()`: Requires implementation of an actual key splitting scheme within this function when used.

`modAvail_CloudServerSide_decrypt()`: Implements the single decryption operation required by the cloud server for the **ModAvail** process.

Note: The Full-$\mathsf{iModel}$'s **ModAvail** process doesn't require AI provider participation, therefore it doesn't include the `modAvail_AIProviderSide()` function.

## Usage

Instantiate the Full_iModel or Semi_iModel class and call the corresponding algorithms. Note that execution requires invoking the actual AI models used in the **ModAvail** and **ModTrain** sections of the respective code.  
