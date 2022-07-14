from DataParser import DataParser
from UI import UI


def main():
    parser = DataParser()
    ui = UI(parser)
    ui.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting programme...")
