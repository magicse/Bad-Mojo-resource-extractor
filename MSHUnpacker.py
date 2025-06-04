import os
import struct
from io import BytesIO

def detect_msh_format(stream: BytesIO) -> int:
    file_size = len(stream.getbuffer())
    if file_size < 4:
        return 0

    # Format 1: 2-byte count
    stream.seek(0)
    count_bytes = stream.read(2)
    if len(count_bytes) < 2:
        return 0
    entry_count_w = struct.unpack('<H', count_bytes)[0]

    if entry_count_w > 0 and 2 + entry_count_w * 18 <= file_size:
        valid = True
        prev_offset = -1
        for i in range(entry_count_w):
            stream.seek(2 + i * 18 + 14)
            curr_offset = struct.unpack('<I', stream.read(4))[0]
            if prev_offset >= 0 and curr_offset <= prev_offset:
                valid = False
            prev_offset = curr_offset
        if valid and curr_offset <= file_size:
            return 1

    # Format 2: 1-byte count
    stream.seek(0)
    entry_count_b = stream.read(1)
    if not entry_count_b:
        return 0
    entry_count_b = entry_count_b[0]

    if entry_count_b > 0 and 1 + entry_count_b * 24 <= file_size:
        valid = True
        prev_offset = -1
        for i in range(entry_count_b):
            stream.seek(1 + i * 24 + 20)
            curr_offset = struct.unpack('<I', stream.read(4))[0]
            if prev_offset >= 0 and curr_offset <= prev_offset:
                valid = False
            prev_offset = curr_offset
        if valid and curr_offset <= file_size:
            return 2

    return 0


def extract_msh_from_stream(stream: BytesIO, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    format_type = detect_msh_format(stream)

    if format_type == 0:
        raise ValueError("Unknown or unsupported MSH format.")

    entries = []
    file_size = len(stream.getbuffer())

    if format_type == 1:
        stream.seek(0)
        entry_count = struct.unpack('<H', stream.read(2))[0]
        for i in range(entry_count):
            name = stream.read(14).split(b'\x00', 1)[0].decode('utf-8', 'ignore').strip()
            offset = struct.unpack('<I', stream.read(4))[0]
            entries.append({'name': name, 'offset': offset})
    elif format_type == 2:
        stream.seek(0)
        entry_count = struct.unpack('<B', stream.read(1))[0]
        for i in range(entry_count):
            name = stream.read(20).split(b'\x00', 1)[0].decode('utf-8', 'ignore').strip()
            offset = struct.unpack('<I', stream.read(4))[0]
            entries.append({'name': name, 'offset': offset})

    # Sizes
    for i in range(len(entries) - 1):
        entries[i]['size'] = entries[i + 1]['offset'] - entries[i]['offset']
    entries[-1]['size'] = file_size - entries[-1]['offset']

    # Extract
    for entry in entries:
        stream.seek(entry['offset'])
        data = stream.read(entry['size'])
        name = entry['name']
        if not name:
            continue
        if not os.path.splitext(name)[1]:
            name += '.bin'

        entry_path = os.path.join(output_dir, name)

        if name.lower().endswith('.msh'):
            try:
                extract_msh_from_stream(BytesIO(data), os.path.join(output_dir, os.path.splitext(name)[0]))
            except Exception as e:
                print(f"Error extracting embedded MSH {name}: {e}")
        else:
            with open(entry_path, 'wb') as f:
                f.write(data)
            print(f"Extracted: {entry_path}")


def extract_msh_file(input_file: str, output_dir: str):
    print(f"Extracting file: {input_file}")
    with open(input_file, 'rb') as f:
        data = f.read()
        extract_msh_from_stream(BytesIO(data), output_dir)
    print("Done.")


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print("Usage: msh_unpacker.py <file.msh> <output_folder>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_folder = sys.argv[2]

    try:
        extract_msh_file(input_file, output_folder)
    except Exception as e:
        print("Error:", e)
