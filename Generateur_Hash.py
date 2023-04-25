# Generateur de Hash

import hashlib
import argparse

#____PARSEUR____
parser = argparse.ArgumentParser(description="Hash Generator")
# parser.add_argument("-0", "--saisir", dest="saisie", help="Saisir le chaine de caractere", required=False) 

parser.add_argument("-h1", "--md5", dest="md5", help="Generer un hash de type md5", required=False) 
parser.add_argument("-h2","--sha1", dest="sha1", help="Generer un hash de type sha1", required=False)
parser.add_argument("-h3", "--sha224", dest="sha224", help="Generer un hash de type sha224", required=False)
parser.add_argument("-h4", "--sha256", dest="sha256", help="Generer un hash de type sha256", required=False)
parser.add_argument("-h5", "--sha384", dest="sha384", help="Generer un hash de type sha384", required=False)
parser.add_argument("-h6", "--sha512", dest="sha512", help="Generer un hash de type sha512", required=False)
parser.add_argument("-h7", "--blake2b", dest="blake2b", help="Generer un hash de type blake2b", required=False)
parser.add_argument("-h8", "--blake2s", dest="blake2s", help="Generer un hash de type blake2s", required=False)
parser.add_argument("-h9", "--sha3_224", dest="sha3_224", help="Generer un hash de type sha3_224", required=False)
parser.add_argument("-h10", "--sha3_256", dest="sha3_256", help="Generer un hash de type sha3_256", required=False)
parser.add_argument("-h11", "--sha3_384", dest="sha3_384", help="Generer un hash de type sha3_384", required=False)
parser.add_argument("-h12", "--sha3_512", dest="sha3_512", help="Generer un hash de type sha3_512", required=False)
#Double_Arg
parser.add_argument("-h13", "--shake_128", dest="shake_128", help="Generer un hash de type Shake_128", required=False)
parser.add_argument("-s128", "--args128", dest="args128", help="Clé de cryptage du Shake_128", required=False, type=int)
#Double_Arg
parser.add_argument("-h14", "--shake_256", dest="shake_256", help="Generer un hash de type Shake_256(key)", required=False)
parser.add_argument("-s256", "--args256", dest="args256", help="Clé de cryptage du Shake_256(key)", required=False, type=int)

args = parser.parse_args()

#____INTERFACE____
class Couleur:
    JAUNE = '\033[1;33m'          
    FIN = '\033[0m'  

print("""
                                            +----------------------------------+
                                            |                                  | 
                                            |          HASH GENERATOR          | 
                                            |                                  |
                                            +----------------------------------+
    """)
print()

#____PROTO____
#_____________ : Simple Arg
if args.md5:
    print(Couleur.JAUNE +"[ Md5 HASH ]: "  + Couleur.FIN+" '"+ args.md5 + "' : " + hashlib.md5(args.md5.encode("utf8")).hexdigest())
    print()
if args.sha1:
    print(Couleur.JAUNE +"[ Sha1 HASH ]: " + Couleur.FIN +" '"+ args.sha1 + "' : " + hashlib.sha1(args.sha1.encode("utf8")).hexdigest())
    print()
if args.sha224:
    print(Couleur.JAUNE +"[ Sha224 HASH ]: " + Couleur.FIN +" '"+ args.sha224 + "' : " + hashlib.sha224(args.sha224.encode("utf8")).hexdigest())
    print()
if args.sha256:
    print(Couleur.JAUNE +"[ Sha256 HASH ]: " + Couleur.FIN +" '"+ args.sha256 + "' : " + hashlib.sha256(args.sha256.encode("utf8")).hexdigest())
    print()
if args.sha384:
    print(Couleur.JAUNE +"[ Sha384 HASH ]: " + Couleur.FIN +" '"+ args.sha384 + "' : " + hashlib.sha384(args.sha384.encode("utf8")).hexdigest())
    print()
if args.sha512:
    print(Couleur.JAUNE +"[ Sha512 HASH ]: " + Couleur.FIN +" '"+ args.sha512 + "' : " + hashlib.sha512(args.sha512.encode("utf8")).hexdigest())
    print()
if args.blake2b:
    print(Couleur.JAUNE +"[ Blake2b HASH ]: " + Couleur.FIN +" '"+ args.blake2b + "' : " + hashlib.blake2b(args.blake2b.encode("utf8")).hexdigest())
    print()
if args.blake2s:
    print(Couleur.JAUNE +"[ Blake2s HASH ]: " + Couleur.FIN +" '"+ args.blake2s + "' : " + hashlib.blake2s(args.blake2s.encode("utf8")).hexdigest())
    print()
if args.sha3_224:
    print(Couleur.JAUNE +"[ Sha3_224 HASH ]: " + Couleur.FIN +" '"+ args.sha3_224 + "' : " + hashlib.sha3_224(args.sha3_224.encode("utf8")).hexdigest())
    print()
if args.sha3_256:
    print(Couleur.JAUNE +"[ Sha3_256 HASH ]: " + Couleur.FIN +" '"+ args.sha3_256 + "' : " + hashlib.sha3_256(args.sha3_256.encode("utf8")).hexdigest())
    print()
if args.sha3_384:
    print(Couleur.JAUNE +"[ Sha3_384 HASH ]: " + Couleur.FIN +" '"+ args.sha3_384 + "' : " + hashlib.sha3_384(args.sha3_384.encode("utf8")).hexdigest())
    print()
if args.sha3_512:
    print(Couleur.JAUNE +"[ Sha3_512 HASH ]: " + Couleur.FIN +" '"+ args.sha3_512 + "' : " + hashlib.sha3_512(args.sha3_512.encode("utf8")).hexdigest())
    print()
#_____________ : Double Arg  
if args.shake_128:
    if args.args128 :
        print(Couleur.JAUNE +"[ Sha3_512 HASH ]: " + Couleur.FIN +" '"+ args.shake_128 + "' : " + hashlib.shake_128(args.shake_128.encode("utf8")).hexdigest(args.args128))
        print()
if args.shake_256:
    if args.args256 :
        print(Couleur.JAUNE +"[ Sha3_512 HASH ]: " + Couleur.FIN +" '"+ args.shake_256 + "' : " + hashlib.shake_256(args.shake_256.encode("utf8")).hexdigest(args.args256))
        print()

