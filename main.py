import re

def is_ipv4_decimal(address):
    parts = address.strip().split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True

def is_ipv4_binary(address):
    parts = address.strip().split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if len(part) !=8:
            return False
        if not all(c in '01' for c in part):
            return False
    return True

def is_ipv4_hex(address):
    address = address.strip()
    if re.fullmatch(r'0x[0-9A-Fa-f]{8}', address):
        return True
    if re.fullmatch(r'([0-9A-Fa-f]{2}\.){3}[0-9A-Fa-f]{2}', address):
        return True
    return False

def is_ipv6_hex(address):
    if re.fullmatch(r'([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}', address.strip()):
        return True
    return False

def is_ipv6_binary(address):
    if re.fullmatch(r'([01]{16}:){7}[01]{16}', address.strip()):
        return True
    return False

def is_mac_hex(address):
    if re.fullmatch(r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', address.strip()):
        return True
    return False

def is_mac_binary(address):
    if re.fullmatch(r'([01]{8}[:\-\.]){5}[01]{8}', address.strip()):
        return True
    return False

def is_mac_decimal(address):
    sep = ':' if ':' in address else '-'
    parts = address.strip().split(sep)
    if len(parts) != 6:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True

def detect_address_type_and_base(address):
    if is_ipv4_decimal(address):
        return ('IPv4', 'decimal')
    elif is_ipv4_binary(address):
        return ('IPv4', 'binary')
    elif is_ipv4_hex(address):
        return ('IPv4', 'hexadecimal')
    elif is_ipv6_hex(address):
        return ('IPv6', 'hexadecimal')
    elif is_ipv6_binary(address):
        return ('IPv6', 'binary')
    elif is_mac_hex(address):
        return ('MAC', 'hexadecimal')
    elif is_mac_binary(address):
        return ('MAC', 'binary')
    elif is_mac_decimal(address):
        return ('MAC', 'decimal')
    else:
        return (None, None)

def ipv4_decimal_to_binary(address):
    parts = address.strip().split('.')
    binary_parts = ['{0:08b}'.format(int(part)) for part in parts]
    return '.'.join(binary_parts)

def ipv4_decimal_to_hex(address):
    parts = address.strip().split('.')
    hex_parts = ['{0:02X}'.format(int(part)) for part in parts]
    return '.'.join(hex_parts)

def ipv4_binary_to_decimal(address):
    parts = address.strip().split('.')
    decimal_parts = [str(int(part, 2)) for part in parts]
    return '.'.join(decimal_parts)

def ipv4_binary_to_hex(address):
    parts = address.strip().split('.')
    hex_parts = ['{0:02X}'.format(int(part, 2)) for part in parts]
    return '.'.join(hex_parts)

def ipv4_hex_to_decimal(address):
    if address.startswith('0x') or address.startswith('0X'):
        address = address[2:]
        parts = [address[i:i+2] for i in range(0,8,2)]
    else:
        parts = address.strip().split('.')
    decimal_parts = [str(int(part, 16)) for part in parts]
    return '.'.join(decimal_parts)

def ipv4_hex_to_binary(address):
    if address.startswith('0x') or address.startswith('0X'):
        address = address[2:]
        parts = [address[i:i+2] for i in range(0,8,2)]
    else:
        parts = address.strip().split('.')
    binary_parts = ['{0:08b}'.format(int(part, 16)) for part in parts]
    return '.'.join(binary_parts)

def ipv6_hex_to_binary(address):
    parts = address.strip().split(':')
    binary_parts = ['{0:016b}'.format(int(part, 16)) for part in parts]
    return ':'.join(binary_parts)

def ipv6_binary_to_hex(address):
    parts = address.strip().split(':')
    hex_parts = ['{0:04X}'.format(int(part, 2)) for part in parts]
    return ':'.join(hex_parts)

def ipv6_hex_to_decimal(address):
    parts = address.strip().split(':')
    decimal_parts = [str(int(part, 16)) for part in parts]
    return ':'.join(decimal_parts)

def ipv6_binary_to_decimal(address):
    parts = address.strip().split(':')
    decimal_parts = [str(int(part, 2)) for part in parts]
    return ':'.join(decimal_parts)

def ipv6_decimal_to_hex(address):
    parts = address.strip().split(':')
    hex_parts = ['{0:04X}'.format(int(part)) for part in parts]
    return ':'.join(hex_parts)

def ipv6_decimal_to_binary(address):
    parts = address.strip().split(':')
    binary_parts = ['{0:016b}'.format(int(part)) for part in parts]
    return ':'.join(binary_parts)

def mac_hex_to_binary(address):
    sep = ':' if ':' in address else '-'
    parts = address.strip().split(sep)
    binary_parts = ['{0:08b}'.format(int(part, 16)) for part in parts]
    return sep.join(binary_parts)

def mac_hex_to_decimal(address):
    sep = ':' if ':' in address else '-'
    parts = address.strip().split(sep)
    decimal_parts = [str(int(part, 16)) for part in parts]
    return sep.join(decimal_parts)

def mac_binary_to_hex(address):
    if ':' in address:
        sep = ':'
    elif '-' in address:
        sep = '-'
    elif '.' in address:
        sep = '.'
    else:
        sep = ''
    parts = address.strip().split(sep)
    hex_parts = ['{0:02X}'.format(int(part, 2)) for part in parts]
    return sep.join(hex_parts)

def mac_binary_to_decimal(address):
    if ':' in address:
        sep = ':'
    elif '-' in address:
        sep = '-'
    elif '.' in address:
        sep = '.'
    else:
        sep = ''
    parts = address.strip().split(sep)
    decimal_parts = [str(int(part, 2)) for part in parts]
    return sep.join(decimal_parts)

def mac_decimal_to_hex(address):
    sep = ':' if ':' in address else '-'
    parts = address.strip().split(sep)
    hex_parts = ['{0:02X}'.format(int(part)) for part in parts]
    return sep.join(hex_parts)

def mac_decimal_to_binary(address):
    sep = ':' if ':' in address else '-'
    parts = address.strip().split(sep)
    binary_parts = ['{0:08b}'.format(int(part)) for part in parts]
    return sep.join(binary_parts)

def convert_address(address, address_type, input_base):
    if address_type == 'IPv4':
        if input_base == 'decimal':
            binary = ipv4_decimal_to_binary(address)
            hexa = ipv4_decimal_to_hex(address)
            return {'binary': binary, 'hexadecimal': hexa}
        elif input_base == 'binary':
            decimal = ipv4_binary_to_decimal(address)
            hexa = ipv4_binary_to_hex(address)
            return {'decimal': decimal, 'hexadecimal': hexa}
        elif input_base == 'hexadecimal':
            decimal = ipv4_hex_to_decimal(address)
            binary = ipv4_hex_to_binary(address)
            return {'decimal': decimal, 'binary': binary}
    elif address_type == 'IPv6':
        if input_base == 'hexadecimal':
            binary = ipv6_hex_to_binary(address)
            decimal = ipv6_hex_to_decimal(address)
            return {'binary': binary, 'decimal': decimal}
        elif input_base == 'binary':
            hexa = ipv6_binary_to_hex(address)
            decimal = ipv6_binary_to_decimal(address)
            return {'hexadecimal': hexa, 'decimal': decimal}
        elif input_base == 'decimal':
            hexa = ipv6_decimal_to_hex(address)
            binary = ipv6_decimal_to_binary(address)
            return {'hexadecimal': hexa, 'binary': binary}
    elif address_type == 'MAC':
        if input_base == 'hexadecimal':
            binary = mac_hex_to_binary(address)
            decimal = mac_hex_to_decimal(address)
            return {'binary': binary, 'decimal': decimal}
        elif input_base == 'binary':
            hexa = mac_binary_to_hex(address)
            decimal = mac_binary_to_decimal(address)
            return {'hexadecimal': hexa, 'decimal': decimal}
        elif input_base == 'decimal':
            hexa = mac_decimal_to_hex(address)
            binary = mac_decimal_to_binary(address)
            return {'hexadecimal': hexa, 'binary': binary}
    else:
        return None

def main():
    address = input("Enter the address: ").strip()
    address_type, input_base = detect_address_type_and_base(address)
    if address_type is None:
        print("Invalid address format.")
        return
    conversions = convert_address(address, address_type, input_base)
    if conversions is None:
        print("Conversion failed.")
        return
    print(f"Address type: {address_type}")
    print(f"Input base: {input_base}")
    for base, converted_address in conversions.items():
        print(f"{base.capitalize()} representation: {converted_address}")

if __name__ == "__main__":
    main()
