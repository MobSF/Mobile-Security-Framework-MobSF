import os
import traceback
import struct
import logging
logger = logging.getLogger(__name__)
# This is a small wraper to help manipulate the qcow2 system image inside the avd
# For more info please refer to - https://people.gnome.org/~markmc/qcow-image-format.html


class Qcow2():
    def __init__(self, path):
        self.path = path
        self.backing_file_str_offset = 0
        self.backing_file_str_size = 0
        self.BACKING_FILE_HEADER = 8
        self.SIZE_HEADER = 16
        self.tmp_backing_str = ''

    def parse_header(self):
        try:
            # The backing file string offset & the size of the string are part of the qcow2 header
            with open(self.path, 'rb') as read_fd:

                # uint64_t
                read_fd.seek(self.BACKING_FILE_HEADER)
                raw_offset = read_fd.read(8)
                self.backing_file_str_offset = struct.unpack('>q', raw_offset)[0]

                # uint32_t
                read_fd.seek(self.SIZE_HEADER)
                raw_offset = read_fd.read(4)
                self.backing_file_str_size = struct.unpack('>i', raw_offset)[0]

                return True
        except:
            logger.error("Qcow2-parse_header: \r\n{}".format(traceback.format_exc()))
            return None

    def get_backing_file_path_str(self):
        try:
            if not (self.backing_file_str_offset and self.backing_file_str_size):
                logger.error("Qcow2-get_backing_file_path_str: offset and size not initialized, run parse_header first")
                return None

            with open(self.path, 'rb') as read_fd:
                read_fd.seek(self.backing_file_str_offset)
                raw_str = read_fd.read(self.backing_file_str_size)
                backing_str = str(raw_str.decode('ascii')).replace('\x00', '')
                self.tmp_backing_str = backing_str
                return backing_str
        except:
            logger.error("Qcow2-get_backing_file_path_str: \r\n{}".format(traceback.format_exc()))
            return None

    def write_new_system_path_inside_qcow(self, new_system_path):
        try:
            # Get the length of the path so we could update the header too
            system_image_str_len = len(new_system_path)

            # Open in override mode so we don't need to read the whole file just to replace a little string
            with open(self.path, 'r+b') as write_fd:
                # First let's update the str size in the header
                write_fd.seek(self.SIZE_HEADER)
                write_fd.write(struct.pack(">i", system_image_str_len))

                # Write the new system.img path
                # There is no termination (we just wrote the size header)
                write_fd.seek(self.backing_file_str_offset)
                write_fd.write(new_system_path.encode('ascii'))

                # optional - Clean up the left overs from the previous string
                # We don't really care about this check so we do it only when we already called get_backing_file_
                # path_str
                if self.tmp_backing_str:
                    if len(self.tmp_backing_str) > system_image_str_len:
                        zeros_to_append = len(self.tmp_backing_str) - system_image_str_len
                        write_fd.write(b'\x00' * zeros_to_append)

                logger.info("New system path was written to qcow file")
                return True
        except:
            logger.error("Qcow2-write_new_system_path_inside_qcow: \r\n{}".format(traceback.format_exc()))
            return False




