XX = /usr/local/mipsCompile/buildroot/output/host/usr/bin/mips-linux-g++ --static -lpthread
PROJECTNAME = iWifiDestoryer
SERVER_OBJS = linux.o $(PROJECTNAME).o

all: clean linux.o $(PROJECTNAME).o wifidestoryer

linux.o:
	$(XX) -c linux.cpp

$(PROJECTNAME).o:
	$(XX) -c $(PROJECTNAME).cpp

wifidestoryer:
	$(XX) $(SERVER_OBJS) -o $(PROJECTNAME)

clean:
	rm -f *.pb.h *.o $(PROJECTNAME)

