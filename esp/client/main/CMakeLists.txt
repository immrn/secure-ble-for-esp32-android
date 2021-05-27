set(srcs "main.c"
        "../../apis/app_gap.c"
        "../../apis/app_l2cap.c"
        "../../apis/app_misc.c"
        "../../apis/app_ssl_ctx.c"
        "../../apis/app_l2cap_io_calls.c"
        "../../apis/sdu_queue.c"
        "../../apis/subscription.c"
        "../../apis/debug_l2cap.c")

idf_component_register(SRCS "${srcs}" 
                    INCLUDE_DIRS "." "../../apis")

# Create a SPIFFS image from the contents of the 'spiffs_image' directory
# that fits the partition named 'storage'. FLASH_IN_PROJECT indicates that
# the generated image should be flashed when the entire project is flashed to
# the target with 'idf.py -p PORT flash'.
spiffs_create_partition_image(storage ../spiffs_image FLASH_IN_PROJECT)