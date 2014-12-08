
wiretap.o:	wiretap.cpp
	g++ -g -std=c++11 -lpcap -o wiretap wiretap.cpp

clean:
	rm wiretap
