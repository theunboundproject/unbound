import struct
import sys

CPU_TYPE_ARM64 = 0x0100000c

def extract_arm64(filename):
    try:
        with open(filename, 'rb') as f:
            magic = f.read(4)
            if magic != b'\xca\xfe\xba\xbe':
                print("Not a FAT binary, nothing to extract.")
                return

            num_archs = struct.unpack('>I', f.read(4))[0]
            for i in range(num_archs):
                data = f.read(20)
                cputype, _, offset, size, _ = struct.unpack('>IIIII', data)
                
                if cputype == CPU_TYPE_ARM64:
                    print(f"🔪 Extracting ARM64 slice ({size} bytes) starting at {offset}...")
                    f.seek(offset)
                    arm64_data = f.read(size)
                    
                    output_name = "extracted_arm64.bin"
                    with open(output_name, 'wb') as out:
                        out.write(arm64_data)
                    print(f"✅ Created: {output_name}")
                    return
            print("❌ Could not find ARM64 slice.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sniffer.py <binary>")
    else:
        extract_arm64(sys.argv[1])