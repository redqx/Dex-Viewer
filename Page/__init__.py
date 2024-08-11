import os
import platform

from PyQt5 import uic
from PyQt5.QtGui import QFontDatabase, QIcon

# diy page
from Page.TabPage import myTabWidget
# for declaration
from PyQt5.QtWidgets import QTabWidget, QFileDialog

from Page.utils import isDexFile
from packages.MsgBox import MsgBox
from packages.log import LOG

PAGE_HOME_UI = "asset/ui/home_widget.ui"
PAGE_WELCOME = "asset/ui/welcome_widget.ui"
ui_PropertyInit, ui_BaseWidget = uic.loadUiType(PAGE_HOME_UI)  # 返回2个类: 属性赋值的类, 基类(继承于Widget) , 要么继承要么实例化


class Page_Home(ui_BaseWidget):  # QMainWindow

    f_tabWidget: QTabWidget

    def __init__(self):
        super().__init__()
        self.f_tabWidget = None
        self.ui = ui_PropertyInit()
        self.ui.setupUi(self)  #把self作为以widget的身份传递进去
        #self.f_mainWindow = uic.loadUi(PAGE_HOME_UI)  # type PyQt5.QtWidgets.QMainWindow

        self.m_msg_binding()
        self.m_field_get()
        self.m_ui_init()
        self.setCentralWidget(uic.loadUi(PAGE_WELCOME))

    def m_field_get(self):
        pass

    def m_ui_init(self):
        self.resize(1200, 800)  # 将窗口大小设置为800 x 600
        self.setWindowIcon(QIcon('asset/img/icon.png'))
        QFontDatabase.addApplicationFont("asset/fonts/Agave-Regular.ttf")
        # 创建一个 QLabel 并设置字体
        # font_id = QtGui.QFontDatabase.addApplicationFont("asset/fonts/Agave-Regular.ttf")
        # font_family = QtGui.QFontDatabase.applicationFontFamilies(font_id)[0]
        # self.font_env = QtGui.QFont(font_family)
        # self.font_env.setPointSize(32)
        # self.font_env.setBold(True)
        # self.root.setFont(self.font_env)

    def m_msg_binding(self):
        self.ui.action_Open_2.triggered['bool'].connect(self.m_action_Open_triggered_func)

    # 手动打开文件
    def m_action_Open_triggered_func(self, xx):
        fpath, filetype = QFileDialog.getOpenFileName(self, "", "", "Dex File (*.dex)") #一个apk中可能含有超级多的dex, 所以就不加载apk了 "Dex File (*.dex);; Apk File (*.apk)"
        self.create_newTab_inTabWidget(fpath)

    # 鼠标拖入事件: 鼠标托入我呢见
    def dragEnterEvent(self, evn):  # 子窗口接受拖拽消息貌似要往父窗口传递
        fpath=evn.mimeData().text()
        LOG.log_info(tag="dragEnterEvent",msg=fpath)
        evn.accept()  #有这个才能显示,不然没效果
        # 鼠标放开执行

    def dropEvent(self, evn):  #放开了再读取
        # self.setWindowTitle('鼠标放开了')
        fpath = evn.mimeData().text()
        if platform.system() == 'Windows':
            fpath=fpath.replace("file:///","") #window平台在我的电脑测试,发现多出这些东西, Linux是正常路径

        LOG.log_info(tag="mouse dropEvent", msg=fpath)
        self.create_newTab_inTabWidget(fpath)

    # def dragMoveEvent(self, evn):
    #     LOG.log_info(msg=f'鼠标移入  {type(evn)} {evn.mimeData().text()}')
    def create_newTab_inTabWidget(self, fpath):
        if fpath:
            if isDexFile(fpath):
                if self.f_tabWidget is None:
                    self.f_tabWidget = myTabWidget()
                    self.f_tabWidget.f_sig_tabOver.connect(self.m_tabWidget_sig_tabOver_func)  # 重新绑定信号, 因为对象已经被销毁了
                self.f_tabWidget.m_create_newTab(fpath)
                self.setCentralWidget(self.f_tabWidget)
            else:
                MsgBox.warning(self,"不是dex文件")

    def m_tabWidget_sig_tabOver_func(self):
        self.f_tabWidget = None
        self.setCentralWidget(uic.loadUi(PAGE_WELCOME))
        pass
