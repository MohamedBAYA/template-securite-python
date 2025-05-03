from scapy.all import get_if_list


def hello_world() -> str:
    """
    Hello world function
    """
    return "hello world"


def choose_interface() -> str:
    """
    Display available interfaces and ask user to choose one
    """
    interfaces = get_if_list()
    print("Interfaces disponibles :")
    for idx, iface in enumerate(interfaces):
        print(f"{idx}: {iface}")

    while True:
        try:
            choice = int(input("Choisis le numéro de l'interface à utiliser : "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
            else:
                print("Choix invalide.")
        except ValueError:
            print("Entrée invalide.")
