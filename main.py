def main():
    import sys
    import os
    import hashlib
    from time import sleep

    if os.name == "nt":
        os.system("color")

    def hash(input, isstring, method):
        if not isstring:
            isfile = os.path.isfile(input)
            if isfile:
                with open(input, "rb") as file:
                    input = file.read()
            elif not isfile:
                return "fail"
        if method == "md5":
            hash = hashlib.md5(input).hexdigest()
        elif method == "sha256":
            hash = hashlib.sha256(input).hexdigest()
        elif method == "sha1":
            hash = hashlib.sha1(input).hexdigest()
        return hash

    def methodselect(alloption):
        print("\nSelect the hash method you wish to use : \n")
        print("       1 : MD5")
        print("       2 : SHA256")
        print("       3 : SHA1")
        if alloption:
            print("       4 : ALL")
        print()
        while True:
            hashselect = input("Enter your choice : ")
            if hashselect == "1":
                hashtype = "MD5"
                break
            elif hashselect == "2":
                hashtype = "SHA256"
                break
            elif hashselect == "3":
                hashtype = "SHA1"
                break
            elif alloption:
                if hashselect == "4":
                    hashtype = "ALL"
                    break
                else:
                    print(COLOR["RED"] + "Invalid Choice." + COLOR["ENDC"])
            else:
                print(COLOR["RED"] + "Invalid Choice." + COLOR["ENDC"])
        print()
        return hashtype

    def clear():
        if os.name == "nt":
            os.system("cls")
        else:
            os.system("clear")

    def leave():
        print(COLOR["RED"] + "Quitting..." + COLOR["ENDC"])
        sleep(1)
        sys.exit()

    COLOR = {
        "BLUE": "\033[94m",
        "GREEN": "\033[92m",
        "RED": "\033[91m",
        "ENDC": "\033[0m",
    }

    def asciiart():
        print(COLOR["RED"] + r"    __  __           __       ______            __    ")
        print(r"   / / / /___ ______/ /_     /_  __/___  ____  / /____")
        print(r"  / /_/ / __ `/ ___/ __ \     / / / __ \/ __ \/ / ___/")
        print(r" / __  / /_/ (__  ) / / /    / / / /_/ / /_/ / (__  ) ")
        print(r"/_/ /_/\__,_/____/_/ /_/    /_/  \____/\____/_/____/  " + COLOR["ENDC"])


    while True:
        asciiart()
        print("\n\nChoose what function you want to use :\n")
        print("       1 : Compare file hashes")
        print("       2 : Validate file hash")
        print("       3 : Validate string hash")
        print("       4 : Hash a file")
        print("       5 : Hash a string")
        print("       6 : Quit\n")

        choice = input("Enter your choice : ")

        if choice == "1":
            hashtype = methodselect(False)

            while True:
                firstfile = input("First file path : ")
                print(COLOR["GREEN"] + f"Hashing ({hashtype})..." + COLOR["ENDC"])
                if hashtype == "MD5":
                    firsthash = hash(firstfile, False, "md5")
                elif hashtype == "SHA256":
                    firsthash = hash(firstfile, False, "sha256")
                elif hashtype == "SHA1":
                    firsthash = hash(firstfile, False, "sha1")
                if firsthash == "fail":
                    print(COLOR["RED"] + "Invalid Path." + COLOR["ENDC"])
                else:
                    break

            while True:
                secondfile = input("Second file path : ")
                print(COLOR["GREEN"] + f"Hashing ({hashtype})..." + COLOR["ENDC"])
                if hashtype == "MD5":
                    secondhash = hash(secondfile, False, "md5")
                elif hashtype == "SHA256":
                    secondhash = hash(secondfile, False, "sha256")
                elif hashtype == "SHA1":
                    secondhash = hash(secondfile, False, "sha1")
                if secondhash == "fail":
                    print(COLOR["RED"] + "Invalid Path." + COLOR["ENDC"])
                else:
                    break

            print()
            if firsthash == secondhash:
                print(COLOR["GREEN"] + "File hashes match!" + COLOR["ENDC"])
            elif firsthash != secondhash:
                print(COLOR["RED"] + "File hashes do not match." + COLOR["ENDC"])
            print(f"First File ({hashtype}): {firsthash}")
            print(f"Second File ({hashtype}): {secondhash}")
            input("Press enter to refresh...")
            clear()

        elif choice == "2":
            hashtype = methodselect(False)

            while True:
                filehash = input("File path : ")
                print(COLOR["GREEN"] + f"Hashing ({hashtype})..." + COLOR["ENDC"])
                if hashtype == "MD5":
                    filehash = hash(filehash, False, "md5")
                elif hashtype == "SHA256":
                    filehash = hash(filehash, False, "sha256")
                elif hashtype == "SHA1":
                    filehash = hash(filehash, False, "sha1")

                if filehash == "fail":
                    print(COLOR["RED"] + "Invalid Path." + COLOR["ENDC"])
                else:
                    break

            validatehash = input("Hash : ")

            print()
            if filehash.lower() == validatehash.lower():
                print(COLOR["GREEN"] + "Hashes match!" + COLOR["ENDC"])
            elif filehash != validatehash:
                print(COLOR["RED"] + "Hashes do not match." + COLOR["ENDC"])
            print(f"File ({hashtype}): {filehash}")
            print(f"Hash ({hashtype}): {validatehash}")
            input("Press enter to refresh...")
            clear()

        elif choice == "3":
            hashtype = methodselect(False)

            string = input("String : ")
            string = string.encode()

            print(COLOR["GREEN"] + f"Hashing ({hashtype})..." + COLOR["ENDC"])
            if hashtype == "MD5":
                stringhash = hash(string, True, "md5")
            elif hashtype == "SHA256":
                stringhash = hash(string, True, "sha256")
            elif hashtype == "SHA1":
                stringhash = hash(string, True, "sha1")

            validatestring = input("Hash : ")

            print()
            if stringhash.lower() == validatestring.lower():
                print(COLOR["GREEN"] + "Hashes match!" + COLOR["ENDC"])
            elif stringhash != validatestring:
                print(COLOR["RED"] + "Hashes do not match." + COLOR["ENDC"])
            print(f"String ({hashtype}): {stringhash}")
            print(f"Hash ({hashtype}): {validatestring}")
            input("Press enter to refresh...")
            clear()

        elif choice == "4":
            hashtype = methodselect(True)

            if hashtype == "ALL":
                while True:
                    filehash = input("File path : ")
                    try:
                        print(COLOR["GREEN"] + "Hashing (MD5)..." + COLOR["ENDC"])
                        md5filehash = hash(filehash, False, "md5")
                        if md5filehash == "fail": raise StopIteration
                        print(COLOR["GREEN"] + "Hashing (SHA256)..." + COLOR["ENDC"])
                        sha256filehash = hash(filehash, False, "sha256")
                        if sha256filehash == "fail": raise StopIteration
                        print(COLOR["GREEN"] + "Hashing (SHA1)..." + COLOR["ENDC"])
                        sha1filehash = hash(filehash, False, "sha1")
                        if sha1filehash == "fail": raise StopIteration
                        break
                    except StopIteration:
                        print(COLOR["RED"] + "Invalid Path." + COLOR["ENDC"])

                print(f"\nFile hash (MD5): {md5filehash}")
                print(f"File hash (SHA256): {sha256filehash}")
                print(f"File hash (SHA1): {sha1filehash}")
                input("Press enter to refresh...")
                clear()

            else:
                while True:
                    filehash = input("File path : ")
                    print(COLOR["GREEN"] + f"Hashing ({hashtype})..." + COLOR["ENDC"])
                    if hashtype == "MD5":
                        filehash = hash(filehash, False, "md5")
                    elif hashtype == "SHA256":
                        filehash = hash(filehash, False, "sha256")
                    elif hashtype == "SHA1":
                        filehash = hash(filehash, False, "sha1")

                    if filehash == "fail":
                        print(COLOR["RED"] + "Invalid Path." + COLOR["ENDC"])
                    else:
                        break

                print(f"\nFile hash ({hashtype}): {filehash}")
                input("Press enter to refresh...")
                clear()


        elif choice == "5":
            hashtype = methodselect(True)

            string = input("String : ")
            string = string.encode()

            if hashtype == "ALL":
                print(COLOR["GREEN"] + "Hashing (MD5)..." + COLOR["ENDC"])
                md5stringhash = hash(string, True, "md5")
                print(COLOR["GREEN"] + "Hashing (SHA256)..." + COLOR["ENDC"])
                sha256stringhash = hash(string, True, "sha256")
                print(COLOR["GREEN"] + "Hashing (SHA1)..." + COLOR["ENDC"])
                sha1stringhash = hash(string, True, "sha1")

                print(f"\nString hash (MD5): {md5stringhash}")
                print(f"String hash (SHA256): {sha256stringhash}")
                print(f"String hash (SHA1): {sha1stringhash}")
                input("Press enter to refresh...")
                clear()

            else:
                print(COLOR["GREEN"] + f"Hashing ({hashtype})..." + COLOR["ENDC"])
                if hashtype == "MD5":
                    stringhash = hash(string, True, "md5")
                elif hashtype == "SHA256":
                    stringhash = hash(string, True, "sha256")
                elif hashtype == "SHA1":
                    stringhash = hash(string, True, "sha1")

                print(f"\nString hash ({hashtype}): {stringhash}")
                input("Press enter to refresh...")
                clear()

        elif choice == "6":
            leave()

        else:
            clear()
            print(COLOR["RED"] + "Invalid Input.\n" + COLOR["ENDC"])


if __name__ == '__main__':
    main()
