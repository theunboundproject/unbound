import struct
import sys

def find_entry_point(filename):
    try:
        with open(filename, 'rb') as f:
            f.seek(16) 
            ncmds = struct.unpack('<I', f.read(4))[0]
            f.seek(32) 

            for i in range(ncmds):
                cmd_start = f.tell()
                cmd_type = struct.unpack('<I', f.read(4))[0]
                cmd_size = struct.unpack('<I', f.read(4))[0]

                # LC_MAIN (0x80000028)
                if cmd_type == 0x80000028:
                    f.seek(cmd_start + 8) # entryoff is 8 bytes into the command
                    entry_offset = struct.unpack('<Q', f.read(8))[0]
                    print(f"🎯 ENTRY POINT FOUND!")
                    print(f"   The app starts at offset: {hex(entry_offset)}")
                    print(f"   In a real iPhone, this is where the code begins.")
                    return
                
                f.seek(cmd_start + cmd_size)
            print("❌ LC_MAIN not found. Might be an older binary format.")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    find_entry_point("extracted_arm64.bin")