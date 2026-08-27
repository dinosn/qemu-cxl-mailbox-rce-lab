#include "qemu/osdep.h"
#include "hw/cxl/cxl_device.h"

int main(void)
{
    const size_t mailbox_payload_register_offset = 0x20;
    const size_t payload_in_device =
        offsetof(CXLType3Dev, cxl_dstate) +
        offsetof(CXLDeviceState, mbox_reg_state) +
        mailbox_payload_register_offset;
    const size_t primary_cci_in_device = offsetof(CXLType3Dev, cci);

    if (primary_cci_in_device < payload_in_device) {
        fprintf(stderr, "unexpected CXLType3Dev layout\n");
        return 2;
    }

    printf("sizeof_QemuMutex=%zu\n", sizeof(QemuMutex));
    printf("sizeof_CXLDeviceState=%zu\n", sizeof(CXLDeviceState));
    printf("CXLType3Dev_cxl_dstate=%zu\n",
           offsetof(CXLType3Dev, cxl_dstate));
    printf("CXLType3Dev_cci=%zu\n", primary_cci_in_device);
    printf("CXLDeviceState_mbox_reg_state=%zu\n",
           offsetof(CXLDeviceState, mbox_reg_state));
    printf("mailbox_payload_register_offset=%zu\n",
           mailbox_payload_register_offset);
    printf("payload_to_primary_cci=%zu\n",
           primary_cci_in_device - payload_in_device);
    printf("command_entry_bytes=%zu\n", sizeof(struct cxl_cmd));
    printf("cxl_cmd_size=%zu\n", sizeof(struct cxl_cmd));
    printf("name_field_offset=%zu\n", offsetof(struct cxl_cmd, name));
    printf("handler_field_offset=%zu\n", offsetof(struct cxl_cmd, handler));
    return 0;
}
