
#CC=gcc
CC=powerpc64-unknown-linux-gnu-gcc
CFLAGS=-Wall -O2 -g -m64
LDFLAGS=-m64

SRC_ps3dm_get_repo_node_val=ps3dm_proxy.c ps3dm_get_repo_node_val.c
OBJ_ps3dm_get_repo_node_val=$(SRC_ps3dm_get_repo_node_val:.c=.o)
TARGET_ps3dm_get_repo_node_val=ps3dm_get_repo_node_val

SRC_ps3dm_aim=ps3dm_proxy.c ps3dm_aim.c
OBJ_ps3dm_aim=$(SRC_ps3dm_aim:.c=.o)
TARGET_ps3dm_aim=ps3dm_aim

SRC_ps3dm_um=ps3dm_proxy.c ps3dm_um.c
OBJ_ps3dm_um=$(SRC_ps3dm_um:.c=.o)
TARGET_ps3dm_um=ps3dm_um

SRC_ps3dm_usb_dongle_auth=ps3dm_proxy.c ps3dm_usb_dongle_auth.c
OBJ_ps3dm_usb_dongle_auth=$(SRC_ps3dm_usb_dongle_auth:.c=.o)
LIB_ps3dm_usb_dongle_auth=-lssl -lcrypto
TARGET_ps3dm_usb_dongle_auth=ps3dm_usb_dongle_auth

SRC_ps3dm_sm=ps3dm_proxy.c ps3dm_sm.c
OBJ_ps3dm_sm=$(SRC_ps3dm_sm:.c=.o)
TARGET_ps3dm_sm=ps3dm_sm

SRC_ps3dm_iim=ps3dm_proxy.c ps3dm_iim.c
OBJ_ps3dm_iim=$(SRC_ps3dm_iim:.c=.o)
TARGET_ps3dm_iim=ps3dm_iim

SRC_ps3dm_srtc=ps3dm_proxy.c ps3dm_srtc.c
OBJ_ps3dm_srtc=$(SRC_ps3dm_srtc:.c=.o)
TARGET_ps3dm_srtc=ps3dm_srtc

SRC_ps3dm_vtrm=ps3dm_proxy.c ps3dm_vtrm.c
OBJ_ps3dm_vtrm=$(SRC_ps3dm_vtrm:.c=.o)
TARGET_ps3dm_vtrm=ps3dm_vtrm

SRC_ps3dm_scm=ps3dm_proxy.c ps3dm_scm.c
OBJ_ps3dm_scm=$(SRC_ps3dm_scm:.c=.o)
TARGET_ps3dm_scm=ps3dm_scm

all: $(TARGET_ps3dm_get_repo_node_val) \
	$(TARGET_ps3dm_aim) \
	$(TARGET_ps3dm_um) \
	$(TARGET_ps3dm_usb_dongle_auth) \
	$(TARGET_ps3dm_sm) \
	$(TARGET_ps3dm_iim) \
	$(TARGET_ps3dm_srtc) \
	$(TARGET_ps3dm_vtrm) \
	$(TARGET_ps3dm_scm)

$(TARGET_ps3dm_get_repo_node_val): $(OBJ_ps3dm_get_repo_node_val)
	$(CC) $(LDFLAGS) -o $@ $^

$(TARGET_ps3dm_aim): $(OBJ_ps3dm_aim)
	$(CC) $(LDFLAGS) -o $@ $^

$(TARGET_ps3dm_um): $(OBJ_ps3dm_um)
	$(CC) $(LDFLAGS) -o $@ $^

$(TARGET_ps3dm_usb_dongle_auth): $(OBJ_ps3dm_usb_dongle_auth)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIB_ps3dm_usb_dongle_auth)

$(TARGET_ps3dm_sm): $(OBJ_ps3dm_sm)
	$(CC) $(LDFLAGS) -o $@ $^

$(TARGET_ps3dm_iim): $(OBJ_ps3dm_iim)
	$(CC) $(LDFLAGS) -o $@ $^

$(TARGET_ps3dm_srtc): $(OBJ_ps3dm_srtc)
	$(CC) $(LDFLAGS) -o $@ $^

$(TARGET_ps3dm_vtrm): $(OBJ_ps3dm_vtrm)
	$(CC) $(LDFLAGS) -o $@ $^

$(TARGET_ps3dm_scm): $(OBJ_ps3dm_scm)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $<

.PHONY: clean
clean:
	rm -f $(OBJ_ps3dm_get_repo_node_val) $(TARGET_ps3dm_get_repo_node_val)
	rm -f $(OBJ_ps3dm_aim) $(TARGET_ps3dm_aim)
	rm -f $(OBJ_ps3dm_um) $(TARGET_ps3dm_um)
	rm -f $(OBJ_ps3dm_usb_dongle_auth) $(TARGET_ps3dm_usb_dongle_auth)
	rm -f $(OBJ_ps3dm_sm) $(TARGET_ps3dm_sm)
	rm -f $(OBJ_ps3dm_iim) $(TARGET_ps3dm_iim)
	rm -f $(OBJ_ps3dm_srtc) $(TARGET_ps3dm_srtc)
	rm -f $(OBJ_ps3dm_vtrm) $(TARGET_ps3dm_vtrm)
	rm -f $(OBJ_ps3dm_scm) $(TARGET_ps3dm_scm)
