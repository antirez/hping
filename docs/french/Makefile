TXT = hping2-fr.8.txt

all: $(TXT)

hping2-fr.8.txt: hping2-fr.8
	#groff -t -e -mandoc -Tlatin1 hping2-fr.8 | col -bx | uniq > hping2-fr.8.txt
	#groff -t -e -mandoc -Tlatin1 hping2-fr.8 | uniq > hping2-fr.8.txt
	groff -t -e -mandoc -Tlatin1 hping2-fr.8 | LC_ALL=fr_FR.ISO-8859-1 col -bx | uniq > hping2-fr.8.txt

clean:
	rm -f *~ $(TXT)
