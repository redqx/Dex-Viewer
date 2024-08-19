import os
import threading

from PyQt5.QtCore import Qt, QPoint
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QTabWidget, QMenu, QAction

from Page.DexAnalyzing import DexAnalyzing
from packages.log import LOG

PAGE_DEX_ANALYZING_UI = "asset/ui/dex_widget.ui"


# 每一次tab销毁,都会被回收,导致需要重新创建
class myTabWidget(QTabWidget):
    # field
    f_sig_tabOver: pyqtSignal = pyqtSignal()  #往父容器发信号,说没有tab了
    f_dexDict: dict
    # method
    #mm_tabBar: QTabBar
    f_menu: QMenu
    f_tab_choose: int

    def __init__(self):
        super().__init__()
        self.f_dexDict = {}
        self.f_tab_choose = -1

        #如果不是成员变量, 会被回收,导致无法显示
        self.action_CloseTab = None
        self.action_CloseAllTabs = None

        self.m_create_menu()
        self.m_msg_binding()

    def m_create_menu(self):

        self.action_CloseTab = QAction("Close Tab")
        self.action_CloseAllTabs = QAction("Close All Tabs")
        self.action_CloseTab.triggered['bool'].connect(self.m_action_CloseTab_triggered_freeTab)
        self.action_CloseAllTabs.triggered['bool'].connect(self.m_action_CloseAllTabs_triggered_freeTabs)

        self.f_menu = QMenu(self)
        self.f_menu.addAction(self.action_CloseTab)
        self.f_menu.addAction(self.action_CloseAllTabs)

        self.tabBar().setContextMenuPolicy(Qt.CustomContextMenu)
        self.tabBar().customContextMenuRequested['QPoint'].connect(self.m_tabBar_customContextMenuRequested_func)

    def m_msg_binding(self):
        pass
        # self.action_CloseAllTabs.triggered['bool'].connect(self.action_CloseAllTabs_triggered_freeTabs)
        # self.action_CloseTab.triggered['bool'].connect(self.action_CloseTab_triggered_freeTab)

    def m_create_newTab(self, fpath: str):

        fname = os.path.basename(fpath)
        # 注意会有重合的名字,
        if fname in self.f_dexDict.keys():
            fname = fname + "$" + str(len(self.f_dexDict))  # 这样构造的fname是不重复的, 因为重复
        dict_tmp = {
            'fpath': fpath,
            'dexobj': DexAnalyzing(fpath, PAGE_DEX_ANALYZING_UI)
        }
        self.f_dexDict.update({fname: dict_tmp})

        #self.widget_DexBaseInfo_workprocess(fname)
        new_tab_idx = self.addTab(dict_tmp['dexobj'].f_widget, fname)  #添加显示的页面
        self.setCurrentIndex(new_tab_idx)

    def m_tabBar_customContextMenuRequested_func(self, pos: QPoint):

        tab_index = self.tabBar().tabAt(pos)  #当前页号

        if tab_index != -1:
            self.f_menu.exec_(self.tabBar().mapToGlobal(pos))  # 显示菜单,好像就没用了
            self.f_tab_choose = tab_index
            LOG.log_info(tag="tab_menu_choose", msg=f"choose {tab_index}")
        else:
            LOG.log_error(tag="tab_menu_choose", msg=f"NO TAB {tab_index}")
        pass

    def m_action_CloseTab_triggered_freeTab(self, checked: bool):


        fname = self.tabText(self.f_tab_choose)
        if len(fname) == 0:
            LOG.log_error(tag="CloseTab", msg=f"NO TAB {self.f_tab_choose}")
            return
        else:
            LOG.log_info(msg=f"record tab_cur = {self.f_tab_choose}")
        self.removeTab(self.f_tab_choose)
        del self.f_dexDict[fname]  # 更新字典

        tab_count = self.count()
        if tab_count > 0:
            self.setCurrentIndex(0)  #g固定显示第一个
        else:
            #self.tabWidget.clear()  # 不知道有没有用, 已经为0,再清空所有的tab
            #self.mainWindow.setCentralWidget(uic.loadUi(PAGE_WELCOME))  # 回来原始页面
            self.f_sig_tabOver.emit()  #发消息
        pass

    def m_action_CloseAllTabs_triggered_freeTabs(self, checked: bool):
        pass
