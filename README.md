# iModel

This is a project written in Java, corresponding to our local simulations of the Semi-$\mathsf{iModel}$ and Full-$\mathsf{iModel}$ constructions. The project includes specific algorithms for both constructions, which can be called and used.

## Project Structure

- a.properties: Elliptic curve parameter file.

- Full_iModel.java: Class defining Full-$\mathsf{iModel}$ and its algorithms.

- Paillier.java: An open-source implementation of the Paillier homomorphic encryption algorithm.

- Semi_iModel.java: Class defining Semi-$\mathsf{iModel}$ and its algorithms.

## Configuration

Ensure that you have correctly configured the JPBC library for pairing-based cryptography in Java.

## Usage

Instantiate the Full_iModel or Semi_iModel class and call the corresponding algorithms. Note that execution requires invoking the actual AI models used in the **ModAvail** and **ModTrain** sections of the respective code.  
