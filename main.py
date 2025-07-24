from ui.contact_list import ContactListWindow
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s:%(funcName)s:%(lineno)d - %(message)s"

)

if __name__ == "__main__":
    app = ContactListWindow()
    app.mainloop()
