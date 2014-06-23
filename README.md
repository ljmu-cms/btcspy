# btcspy

Electrum Bitcoin wallet history extractor.

## Introduction

The btcspy script is used for spying on Bitcoin (BTC) wallets. In particular, it will look for the Electrum Bitcoin wallet and list the transaction history stored in it. The history can be extracted even if the wallet has been encrypted or Electrum has been uninstalled by the user.

Electrum is open source software written in Python, and much of the code for btcspy has been taken from its sourcecode. The code has been altered to make it more forensically sound. Unlike Electrum it doesn’t access the network or write files to disc. However, it’s only a proof of concept, and needs more development and testing.

At present btcspy works on Linux and Windows. It should also work on Android wallets, but this hasn’t been tested.

## Standalone use

To use btcspy as a standalone utility, simply execute it as a python script. Open a command window in the btcspy folder (you can do this by Shift-Right-Clicking on the folder and selecting **Open command window here** from the menu). Then type the following.
```
btcspy.ph
```
For help type:
```
btcspy.ph --help
```
A list of transactions will then be output in JSON format.  The txid entry can be used to match the transaction against the public blockchain, for example using a service such as https://blockchain.info/ . The blockchain provides externally validated details about the time, recipient and Bitcoin IDs used in the transaction.

## Use within other Python programs

btcspy can also be used as a library within other Python programs. You can import it and then store the history in a variable called result using the following code.
```
import btcspy
result = btcspy.history()
```
Note that the btcspy code must be in the same folder as your program, or installed in the Python library path, in order for it to be used this way.

## Use with the Python command line interpreter

The same method can be used to execute the script from the Python interpreter. The easiest way to ensure the interpreter can find the script is to run the Python interpreter inside the folder where the script is stored. The type the following to test it out.
```
import btcspy
result = btcspy.history()
print (result)
```

## Contact

For more information about btcspy, please feel free to get in contact.

* David Llewellyn-Jones: D.Llewellyn-Jones@ljmu.ac.uk

* Liverpool John Moores University: http://www.ljmu.ac.uk/cmp/

* PROTECT Research Centre: http://protect-ci.org/

* ECENTRE Project: http://www.ecentre.eu/

* Personal page: http://www.flypig.co.uk

This work has been undertaken with the financial support of the Prevention of and Fight against Crime Programme European Commission - Directorate-General Home Affairs.

