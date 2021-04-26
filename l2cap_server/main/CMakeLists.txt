set(srcs "main.c"
        "../../esp_apis/app_gap.c"
        "../../esp_apis/app_l2cap.c"
        "../../esp_apis/app_misc.c"
        "../../esp_apis/ssl_ctx.c"
        "../../esp_apis/sdu_queue.c")

idf_component_register(SRCS "${srcs}" 
                    INCLUDE_DIRS "." "../../esp_apis")

# Create a SPIFFS image from the contents of the 'spiffs_image' directory
# that fits the partition named 'storage'. FLASH_IN_PROJECT indicates that
# the generated image should be flashed when the entire project is flashed to
# the target with 'idf.py -p PORT flash'.
spiffs_create_partition_image(storage ../spiffs_image FLASH_IN_PROJECT)