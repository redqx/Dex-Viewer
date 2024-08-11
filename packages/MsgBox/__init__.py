from PyQt5.QtWidgets import QMessageBox, QWidget


class MsgBox:
    def __init__(self):
        super().__init__()

    @classmethod
    def warning(self, parent_weidget, info):
        QMessageBox.warning(parent_weidget, "", info, QMessageBox.Yes)

    def __xx(self):
        # QMessageBox.information(self, '1', '1', QMessageBox.Yes)
        # QMessageBox.critical(self, "2", "2", QMessageBox.Open | QMessageBox.Close | QMessageBox.Save)
        # QMessageBox.question(self, "3", "4", QMessageBox.Yes | QMessageBox.No)
        pass
