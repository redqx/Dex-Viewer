import os

from PyQt5 import uic
from PyQt5.QtWidgets import QWidget, QTreeWidgetItem, QTableWidgetItem, QTextBrowser
from PyQt5.QtCore import pyqtSignal, QObject
from packages.dexparser import Dexparser
from Page.utils import org2Hex, man_show
#from packages.hexdump.hexdump import hexdump
from packages.hexdump2 import hexdump
from packages.log import LOG


class DexAnalyzing(QObject): # 文件解析结果 + widget 对象
    f_fname: str
    f_widget: QWidget
    f_dex_parser: Dexparser
    f_sig_showhex: pyqtSignal = pyqtSignal(bytes,int)  # 往父容器发信号,说没有tab了


    def __init__(self, dex_fpath: str, ui_path: str):

        super().__init__()

        # 最好加一个异常处理, 不然看上去没水平
        self.f_fname = os.path.basename(dex_fpath)
        self.f_widget = uic.loadUi(ui_path)
        self.f_dex_parser = Dexparser(dex_fpath)
        self.m_msg_binding()
        self.m_ui_init()

    def m_msg_binding(self):
        self.f_widget.treeWidget_Dex.itemClicked['QTreeWidgetItem*', 'int'].connect(
            self.m_treeWidget_Dex_itemClicked_func)  # type: ignore
        self.f_dex_parser.sig_cost.connect(self.m_showProcessBar)

        self.f_sig_showhex.connect(self.m_showHex_intextBrowser)
        #self.f_sig_showhex.emit()

    def m_ui_init(self):
        self.m_deal_tableWidget_DexBaseInfo()
        # hex view
        self.f_dex_parser.file.seek(0)
        self.f_sig_showhex.emit(self.f_dex_parser.file.read(), 0)
        self.f_widget.stackedWidget_Dex.setCurrentWidget(self.f_widget.widget_DexBaseInfo)

        #self.f_widget.textEdit_hexTitle.textChanged.connect(self.__update_height)
        text1=" offset  | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F |.....ascii......|"
        self.f_widget.textBrowser_hexTitle.setText(text1)
        self.f_widget.textBrowser_hexTitle.setFixedHeight(25)#一个固定的大小,目前还不知道如何根据内容高度自适应

        pass

    def m_treeWidget_Dex_itemClicked_func(self, item: QTreeWidgetItem, column: int):

        item_choose = item.text(column)
        if item_choose == "base-info":
            if self.f_widget.stackedWidget_Dex.currentWidget().objectName() != "widget_DexBaseInfo":
                self.m_deal_tableWidget_DexBaseInfo()
                # hex view
                self.f_dex_parser.file.seek(0)
                self.f_sig_showhex.emit(self.f_dex_parser.file.read(), 0)
                self.f_widget.stackedWidget_Dex.setCurrentWidget(self.f_widget.widget_DexBaseInfo)

        if item_choose == "dex-header":  #dex header
            if self.f_widget.stackedWidget_Dex.currentWidget().objectName() != "widget_DexHeader":
                # 写入数据? 有没有必要每次写入数据呢? 没必要吧
                self.m_deal_tableWidget_DexHeader()
                # hex view
                self.f_sig_showhex.emit(
                    self.f_dex_parser.data[:self.f_dex_parser.dex_header.data_off._end_position_], 0
                )
                self.f_widget.stackedWidget_Dex.setCurrentWidget(self.f_widget.widget_DexHeader)


        elif item_choose == "string-ids":
            if self.f_widget.stackedWidget_Dex.currentWidget().objectName() != "widget_Dex_strids":
                self.m_deal_tableWidget_Dex_strids()
                self.f_sig_showhex.emit(
                    self.f_dex_parser.data[
                    self.f_dex_parser.dex_header.string_ids_off.value:
                    self.f_dex_parser.dex_string_ids[-1].string_data_off._end_position_],
                    self.f_dex_parser.dex_header.string_ids_off.value
                )
                self.f_widget.stackedWidget_Dex.setCurrentWidget(self.f_widget.widget_Dex_strids)
        elif item_choose == "type-ids":
            if self.f_widget.stackedWidget_Dex.currentWidget().objectName() != "widget_Dex_typeids":
                self.m_deal_tableWidget_Dex_typeids()
                self.f_sig_showhex.emit(
                    self.f_dex_parser.data[
                    self.f_dex_parser.dex_header.type_ids_off.value:
                    self.f_dex_parser.dex_type_ids[-1].descriptor_idx._end_position_],
                    self.f_dex_parser.dex_header.type_ids_off.value
                )
                self.f_widget.stackedWidget_Dex.setCurrentWidget(self.f_widget.widget_Dex_typeids)
        elif item_choose == "proto-ids":
            if self.f_widget.stackedWidget_Dex.currentWidget().objectName() != "widget_Dex_protoids":
                self.m_deal_tableWidget_Dex_protoids()
                self.f_sig_showhex.emit(
                    self.f_dex_parser.data[
                    self.f_dex_parser.dex_header.proto_ids_off.value:
                    self.f_dex_parser.dex_proto_ids[-1].parameters_off._end_position_],
                    self.f_dex_parser.dex_header.proto_ids_off.value
                )
                self.f_widget.stackedWidget_Dex.setCurrentWidget(self.f_widget.widget_Dex_protoids)
        elif item_choose == "field-ids":
            if self.f_widget.stackedWidget_Dex.currentWidget().objectName() != "widget_Dex_fieldids":
                self.m_deal_tableWidget_Dex_fieldids()
                self.f_sig_showhex.emit(
                    self.f_dex_parser.data[
                    self.f_dex_parser.dex_header.field_ids_off.value:
                    self.f_dex_parser.dex_field_ids[-1].name_idx._end_position_],
                    self.f_dex_parser.dex_header.field_ids_off.value
                )
                self.f_widget.stackedWidget_Dex.setCurrentWidget(self.f_widget.widget_Dex_fieldids)
        elif item_choose == "method-ids":
            if self.f_widget.stackedWidget_Dex.currentWidget().objectName() != "widget_Dex_methodids":
                self.m_deal_tableWidget_Dex_methodids()
                self.f_sig_showhex.emit(
                    self.f_dex_parser.data[
                    self.f_dex_parser.dex_header.method_ids_off.value:
                    self.f_dex_parser.dex_method_ids[-1].name_idx._end_position_],
                    self.f_dex_parser.dex_header.method_ids_off.value
                )
                self.f_widget.stackedWidget_Dex.setCurrentWidget(self.f_widget.widget_Dex_methodids)
        elif item_choose == "class-defs":
            if self.f_widget.stackedWidget_Dex.currentWidget().objectName() != "widget_Dex_classdefs":
                self.m_deal_tablelWidget_Dex_classdefs()
                self.f_widget.stackedWidget_Dex.setCurrentWidget(self.f_widget.widget_Dex_classdefs)
        elif item_choose == "map-lists":
            if self.f_widget.stackedWidget_Dex.currentWidget().objectName() != "widget_Dex_maplists":
                self.m_deal_tableWidget_Dex_maplists()
                self.f_sig_showhex.emit(
                    self.f_dex_parser.data[
                    self.f_dex_parser.dex_header.map_off.value + 4:
                    self.f_dex_parser.dex_map_list[-1].offset._end_position_],
                    self.f_dex_parser.dex_header.map_off.value + 4
                )
                self.f_widget.stackedWidget_Dex.setCurrentWidget(self.f_widget.widget_Dex_maplists)

    #=======================================================================================

    def m_deal_tableWidget_DexBaseInfo(self):
        item: QTableWidgetItem = self.f_widget.tableWidget_DexBaseInfo.item(0, 0)
        if item is not None:  # 不知道为什么第一次加载中,item为空
            return
        LOG.log_info(tag="QTableWidget", msg="Dex base info init")
        self.m_deal_tableWidget_DexBaseInfo_thread()
        self.f_dex_parser.sig_cost.emit(1)
        # 还没有去处理只能加载一次的情况

    def m_deal_tableWidget_DexHeader(self):
        item: QTableWidgetItem = self.f_widget.tableWidget_DexHeader.item(0, 0)
        if item is not None:  # 不知道为什么第一次加载中,item为空
            return
        #加载,不显示
        LOG.log_info(tag="QTableWidget", msg="Dex_Header init")
        self.m_deal_tableWidget_DexHeader_thread()
        self.f_dex_parser.sig_cost.emit(1)
        # 还没有去处理只能加载一次的情况

    def m_deal_tableWidget_Dex_strids(self):
        if self.f_widget.tableWidget_Dex_strids.rowCount() != 0:
            return
        LOG.log_info(tag="QTableWidget", msg="Dex_strids init")
        self.m_deal_tableWidget_Dex_string_ids_thread()
        self.f_dex_parser.sig_cost.emit(1)

    def m_deal_tableWidget_Dex_typeids(self):
        if self.f_widget.tableWidget_Dex_typeids.rowCount() != 0:
            return
        #env
        LOG.log_info(tag="QTableWidget", msg="Dex_typeids init")
        self.deal_tableWidget_Dex_typeids_thread()
        self.f_dex_parser.sig_cost.emit(1)  # 进度展示

    def m_deal_tableWidget_Dex_protoids(self):
        if self.f_widget.tableWidget_Dex_protoids.rowCount() != 0:
            return
        #env

        LOG.log_info(tag="QTableWidget", msg="Dex_protoids init")
        self.m_deal_tableWidget_Dex_protoids_thread()
        self.f_dex_parser.sig_cost.emit(1)

    def m_deal_tableWidget_Dex_fieldids(self):
        if self.f_widget.tableWidget_Dex_fieldids.rowCount() != 0:
            return
        LOG.log_info(tag="QTableWidget", msg="Dex_fieldids init")
        self.m_deal_tableWidget_Dex_fieldids_thread()
        self.f_dex_parser.sig_cost.emit(1)

    def m_deal_tableWidget_Dex_methodids(self):
        if self.f_widget.tableWidget_Dex_methodids.rowCount() != 0:
            return
        LOG.log_info(tag="QTableWidget", msg="Dex_methodids init")
        self.m_deal_tableWidget_Dex_methodids_thread()
        self.f_dex_parser.sig_cost.emit(1)

    def m_deal_tablelWidget_Dex_classdefs(self):
        return
        # if self.f_widget.tableWidget_Dex_classdefs.rowCount() != 0:
        #     return
        LOG.log_info(tag="QTableWidget", msg="Dex_classdefs init")
        self.m_deal_tablelWidget_Dex_classdefs_thread()
        self.f_dex_parser.sig_cost.emit(1)

    def m_deal_tableWidget_Dex_maplists(self):
        if self.f_widget.tableWidget_Dex_maplists.rowCount() != 0:
            return
        LOG.log_info(tag="QTableWidget", msg="Dex_maplists init")
        self.m_deal_tableWidget_Dex_maplists_thread()
        self.f_dex_parser.sig_cost.emit(1)


    def m_showHex_intextBrowser(self, bytes_data, arg_offset):
        # []{org:str, hex:str}
        more = ""
        hex_data = hexdump(bytes_data[:0x400], result = 'return', offset=arg_offset)#最多显示0x1000, 这不是控制台,不能用 color=True
        if len( bytes_data) > 0x400 :
            more = " | ...more"
        self.f_widget.textBrowser_HexView.setText(hex_data + more)#数据太多会特别卡顿

    # 打开dex,显示最基本的信息
    def m_deal_tableWidget_DexBaseInfo_thread(self) -> bool:

        # 虽然可以在designer中设定,但是会导致designer显示特别大
        self.f_widget.treeWidget_Dex.setMinimumWidth(300)
        self.f_widget.treeWidget_Dex.setMinimumHeight(600)

        # TODO 优化

        #self.tableWidget_DexBaseInfo.verticalHeader().setVisible(False) # 行头不可见
        #self.tableWidget_DexBaseInfo.horizontalHeader().setVisible(False) # 列头不可见

        #设置水平方向表格为自适应的伸缩模式,效果不是水平方向和内容长度自适应,而是直接把水平方向长度最大化
        #self.tableWidget_DexBaseInfo.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        dex_fname = self.f_fname
        dex_fsize = self.f_dex_parser.dex_header.file_size.value
        dex_magic = self.f_dex_parser.dex_header.magic._data_
        dex_checksum = self.f_dex_parser.dex_header.checksum.value
        dex_signature = self.f_dex_parser.dex_header.signature._data_

        item_file_name = QTableWidgetItem(dex_fname)
        item_file_size_ = QTableWidgetItem(man_show(dex_fsize))
        item_magic_ = QTableWidgetItem(man_show(dex_magic))
        item_checksum_ = QTableWidgetItem(org2Hex(dex_checksum))
        item_signature_ = QTableWidgetItem(org2Hex(dex_signature))

        #指定row和col比较的快,但加兼容性不是很好
        # (0,1) 0行1列
        self.f_widget.tableWidget_DexBaseInfo.setItem(0, 0, item_file_name)
        self.f_widget.tableWidget_DexBaseInfo.setItem(1, 0, item_file_size_)
        self.f_widget.tableWidget_DexBaseInfo.setItem(2, 0, item_magic_)
        self.f_widget.tableWidget_DexBaseInfo.setItem(3, 0, item_checksum_)
        self.f_widget.tableWidget_DexBaseInfo.setItem(4, 0, item_signature_)

        #在QTableWidget.setItem之后执行,在之前执行是没效果的
        self.f_widget.tableWidget_DexBaseInfo.resizeColumnsToContents()
        self.f_widget.tableWidget_DexBaseInfo.resizeRowsToContents()


    def m_deal_tableWidget_DexHeader_thread(self):

        item_arr = []
        item_arr.append(QTableWidgetItem(org2Hex(self.f_dex_parser.dex_header.magic._data_)))
        item_arr.append(QTableWidgetItem(org2Hex(self.f_dex_parser.dex_header.checksum.value)))
        item_arr.append(QTableWidgetItem(org2Hex(self.f_dex_parser.dex_header.signature._data_)))
        item_arr.append(QTableWidgetItem(hex(self.f_dex_parser.dex_header.file_size.value)))
        item_arr.append(QTableWidgetItem(hex(self.f_dex_parser.dex_header.header_size.value)))
        item_arr.append(QTableWidgetItem(hex(self.f_dex_parser.dex_header.endian_tag.value)))
        item_arr.append(QTableWidgetItem(str(self.f_dex_parser.dex_header.link_size.value)))
        item_arr.append(QTableWidgetItem(hex(self.f_dex_parser.dex_header.link_off.value)))
        item_arr.append(QTableWidgetItem(hex(self.f_dex_parser.dex_header.map_off.value)))
        item_arr.append(QTableWidgetItem(str(self.f_dex_parser.dex_header.string_ids_size.value)))
        item_arr.append(QTableWidgetItem(hex(self.f_dex_parser.dex_header.string_ids_off.value)))
        item_arr.append(QTableWidgetItem(str(self.f_dex_parser.dex_header.type_ids_size.value)))
        item_arr.append(QTableWidgetItem(hex(self.f_dex_parser.dex_header.type_ids_off.value)))
        item_arr.append(QTableWidgetItem(str(self.f_dex_parser.dex_header.proto_ids_size.value)))
        item_arr.append(QTableWidgetItem(hex(self.f_dex_parser.dex_header.proto_ids_off.value)))
        item_arr.append(QTableWidgetItem(str(self.f_dex_parser.dex_header.field_ids_size.value)))
        item_arr.append(QTableWidgetItem(hex(self.f_dex_parser.dex_header.field_ids_off.value)))
        item_arr.append(QTableWidgetItem(str(self.f_dex_parser.dex_header.method_ids_size.value)))
        item_arr.append(QTableWidgetItem(hex(self.f_dex_parser.dex_header.method_ids_off.value)))
        item_arr.append(QTableWidgetItem(str(self.f_dex_parser.dex_header.class_defs_size.value)))
        item_arr.append(QTableWidgetItem(hex(self.f_dex_parser.dex_header.class_defs_off.value)))
        item_arr.append(QTableWidgetItem(str(self.f_dex_parser.dex_header.data_size.value)))
        item_arr.append(QTableWidgetItem(hex(self.f_dex_parser.dex_header.data_off.value)))

        for i in range(23):
            self.f_widget.tableWidget_DexHeader.setItem(i, 0, item_arr[i])

        #self.tableWidget_DexHeader.resizeColumnsToContents()
        #self.tableWidget_DexHeader.resizeRowsToContents()


    def m_deal_tableWidget_Dex_string_ids_thread(self):

        string_ids = self.f_dex_parser.dex_init_string_ids()
        str_ids_len = len(string_ids)

        self.f_widget.tableWidget_Dex_strids.setRowCount(str_ids_len)

        for i in range(str_ids_len):
            # # 在ui文件中,默认设置了1行的
            # row_cnt = self.tableWidget_Dex_strids.rowCount()
            # self.tableWidget_Dex_strids.insertRow(row_cnt)
            self.f_widget.tableWidget_Dex_strids.setItem(i, 0, QTableWidgetItem(str(i)))  # c_size
            # self.f_widget.tableWidget_Dex_strids.setItem(i, 1, QTableWidgetItem(hex(string_ids[i].string_data_off.value)))  # c_size
            # self.f_widget.tableWidget_Dex_strids.setItem(i, 2, QTableWidgetItem(str(string_ids[i].string_data_off.info.len_size._data_)))  # size_off
            # 一次性显示的数据可能太大太大, 会导致界面卡顿
            self.f_widget.tableWidget_Dex_strids.setItem(i, 1, QTableWidgetItem(string_ids[i].string_data_off.info.str_cbytes.str[:256]))  # c_char 最多取长度32

            self.f_dex_parser.sig_cost.emit(i / str_ids_len)
            # QThread.sleep(1)
            # QApplication.processEvents()
        # self.tableWidget_Dex_strids.resizeColumnsToContents()
        # self.tableWidget_Dex_strids.resizeRowsToContents()

        self.f_dex_parser.sig_cost.emit(1)


    def deal_tableWidget_Dex_typeids_thread(self):

        type_ids = self.f_dex_parser.dex_init_type_ids()
        type_ids_len = len(type_ids)
        self.f_widget.tableWidget_Dex_typeids.setRowCount(type_ids_len)

        for i in range(type_ids_len):
            # # 在ui文件中,默认设置了1行的
            #row_cnt = self.tableWidget_Dex_typeids.rowCount()
            #self.tableWidget_Dex_typeids.insertRow(row_cnt)
            self.f_widget.tableWidget_Dex_typeids.setItem(i, 0, QTableWidgetItem(str(i)))  # c_size
            # self.f_widget.tableWidget_Dex_typeids.setItem(i, 1, QTableWidgetItem(str(type_ids[i].descriptor_idx.value)))  # size_off
            # self.f_widget.tableWidget_Dex_typeids.setItem(i, 2, QTableWidgetItem(type_ids[i].descriptor_idx.info['type_str']))  # c_char
            self.f_widget.tableWidget_Dex_typeids.setItem(i, 1, QTableWidgetItem(type_ids[i].descriptor_idx.info['full_type_str']))

            self.f_dex_parser.sig_cost.emit(i / type_ids_len)  #进度展示

        #self.tableWidget_Dex_typeids.resizeColumnsToContents()
        #self.tableWidget_Dex_typeids.resizeRowsToContents()

    def m_deal_tableWidget_Dex_protoids_thread(self):
        proto_ids = self.f_dex_parser.dex_init_proto_ids()
        proto_ids_len = len(proto_ids)
        self.f_widget.tableWidget_Dex_protoids.setRowCount(proto_ids_len)

        for i in range(proto_ids_len):
            # # 在ui文件中,默认设置了1行的
            #row_cnt = self.tableWidget_Dex_protoids.rowCount()
            #self.tableWidget_Dex_protoids.insertRow(row_cnt)
            self.f_widget.tableWidget_Dex_protoids.setItem(i, 0, QTableWidgetItem(str(i)))  # c_size
            # self.f_widget.tableWidget_Dex_protoids.setItem(i, 1, QTableWidgetItem(str(proto_ids[i].shorty_idx.value)))  # size_off
            # self.f_widget.tableWidget_Dex_protoids.setItem(i, 2, QTableWidgetItem(str(proto_ids[i].return_type_idx.value)))  # c_char
            # self.f_widget.tableWidget_Dex_protoids.setItem(i, 3, QTableWidgetItem(hex(proto_ids[i].parameters_off.value)))  # c_char
            self.f_widget.tableWidget_Dex_protoids.setItem(i, 1, QTableWidgetItem(proto_ids[i].info))  # c_char

            self.f_dex_parser.sig_cost.emit(i / proto_ids_len)  #进度展示
        #self.tableWidget_Dex_protoids.resizeColumnsToContents()
        #self.tableWidget_Dex_protoids.resizeRowsToContents()

    def m_deal_tableWidget_Dex_fieldids_thread(self):

        field_ids = self.f_dex_parser.dex_init_field_ids()
        field_ids_len = len(field_ids)
        self.f_widget.tableWidget_Dex_fieldids.setRowCount(field_ids_len)

        for i in range(field_ids_len):
            # # 在ui文件中,默认设置了1行的
            #row_cnt = self.tableWidget_Dex_fieldids.rowCount()
            #self.tableWidget_Dex_fieldids.insertRow(row_cnt)
            self.f_widget.tableWidget_Dex_fieldids.setItem(i, 0, QTableWidgetItem(str(i)))  # c_size
            # self.f_widget.tableWidget_Dex_fieldids.setItem(i, 1, QTableWidgetItem(str(field_ids[i].class_idx.value)))  # size_off
            # self.f_widget.tableWidget_Dex_fieldids.setItem(i, 2, QTableWidgetItem(str(field_ids[i].type_idx.value)))  # c_char
            # self.f_widget.tableWidget_Dex_fieldids.setItem(i, 3, QTableWidgetItem(str(field_ids[i].name_idx.value)))  # c_char
            self.f_widget.tableWidget_Dex_fieldids.setItem(i, 1, QTableWidgetItem(field_ids[i].info))  # c_char

            self.f_dex_parser.sig_cost.emit(i / field_ids_len)  #进度展示
        #self.tableWidget_Dex_fieldids.resizeColumnsToContents()
        #self.tableWidget_Dex_fieldids.resizeRowsToContents()

    def m_deal_tableWidget_Dex_methodids_thread(self):
        method_ids = self.f_dex_parser.dex_init_method_ids()
        method_ids_len = len(method_ids)
        self.f_widget.tableWidget_Dex_methodids.setRowCount(method_ids_len)

        for i in range(method_ids_len):
            # # 在ui文件中,默认设置了1行的
            #row_cnt = self.tableWidget_Dex_methodids.rowCount()
            #self.tableWidget_Dex_methodids.insertRow(row_cnt)
            self.f_widget.tableWidget_Dex_methodids.setItem(i, 0, QTableWidgetItem(str(i)))  # c_size
            # self.f_widget.tableWidget_Dex_methodids.setItem(i, 1, QTableWidgetItem( str(method_ids[i].class_idx.value)))  # size_off
            # self.f_widget.tableWidget_Dex_methodids.setItem(i, 2,  QTableWidgetItem(str(method_ids[i].proto_idx.value)))  # c_char
            # self.f_widget.tableWidget_Dex_methodids.setItem(i, 3,  QTableWidgetItem(str(method_ids[i].name_idx.value)))  # c_char
            self.f_widget.tableWidget_Dex_methodids.setItem(i, 1,  QTableWidgetItem( method_ids[i].info))  # c_char

            self.f_dex_parser.sig_cost.emit(i / method_ids_len)  #进度展示
        #resizeColumnsToContents()
        #self.tableWidget_Dex_methodids.resizeRowsToContents()

    def m_deal_tablelWidget_Dex_classdefs_thread(self):

        classdef_ids = self.f_dex_parser.dex_init_classdef_ids()
        classdef_ids_len = len(classdef_ids)
        self.f_widget.tableWidget_Dex_classdefs.setRowCount(classdef_ids_len)
        for i in range(classdef_ids_len):
            # # 在ui文件中,默认设置了1行的
            #row_cnt = self.tablelWidget_Dex_classdefs.rowCount()
            #self.tablelWidget_Dex_classdefs.insertRow(row_cnt)
            self.f_widget.tableWidget_Dex_classdefs.setItem(i, 0, QTableWidgetItem(str(i)))  # c_size
            self.f_widget.tableWidget_Dex_classdefs.setItem(i, 1, QTableWidgetItem(str(classdef_ids[i]['class_idx'])))  # size_off
            self.f_widget.tableWidget_Dex_classdefs.setItem(i, 2, QTableWidgetItem(str(classdef_ids[i]['access'])))  # c_char
            self.f_widget.tableWidget_Dex_classdefs.setItem(i, 3, QTableWidgetItem(str(classdef_ids[i]['superclass_idx'])))
            self.f_widget.tableWidget_Dex_classdefs.setItem(i, 4, QTableWidgetItem(hex(classdef_ids[i]['interfaces_off'])))
            self.f_widget.tableWidget_Dex_classdefs.setItem(i, 5, QTableWidgetItem(str(classdef_ids[i]['source_file_idx'])))
            self.f_widget.tableWidget_Dex_classdefs.setItem(i, 6, QTableWidgetItem(hex(classdef_ids[i]['annotation_off'])))
            self.f_widget.tableWidget_Dex_classdefs.setItem(i, 7, QTableWidgetItem(hex(classdef_ids[i]['class_data_off'])))
            self.f_widget.tableWidget_Dex_classdefs.setItem(i, 8, QTableWidgetItem(hex(classdef_ids[i]['static_values_off'])))
            self.f_widget.tableWidget_Dex_classdefs.setItem(i, 9, QTableWidgetItem(classdef_ids[i]['full_class_name']))

            self.f_dex_parser.sig_cost.emit(i / classdef_ids_len)  #进度展示

        #self.tableWidget_Dex_classdefs.resizeColumnsToContents()
        #self.tableWidget_Dex_classdefs.resizeRowsToContents()

    def m_deal_tableWidget_Dex_maplists_thread(self):

        map_lists = self.f_dex_parser.dex_init_maplist()
        map_lists_len = len(map_lists)
        self.f_widget.tableWidget_Dex_maplists.setRowCount(map_lists_len)
        for i in range(map_lists_len):
            # # 在ui文件中,默认设置了1行的
            #row_cnt = self.tableWidget_Dex_maplists.rowCount()
            #self.tableWidget_Dex_maplists.insertRow(row_cnt)
            self.f_widget.tableWidget_Dex_maplists.setItem(i, 0, QTableWidgetItem(str(i)))  # c_size
            self.f_widget.tableWidget_Dex_maplists.setItem(i, 1, QTableWidgetItem(hex(map_lists[i].type.value)))  # size_off
            self.f_widget.tableWidget_Dex_maplists.setItem(i, 2, QTableWidgetItem(str(map_lists[i].unused.value)))  # c_char
            self.f_widget.tableWidget_Dex_maplists.setItem(i, 3, QTableWidgetItem(str(map_lists[i].size.value)))  # c_char
            self.f_widget.tableWidget_Dex_maplists.setItem(i, 4, QTableWidgetItem(hex(map_lists[i].offset.value)))
            self.f_widget.tableWidget_Dex_maplists.setItem(i, 5, QTableWidgetItem(map_lists[i].info))

            self.f_dex_parser.sig_cost.emit(i / map_lists_len)  #进度展示

        #self.tableWidget_Dex_maplists.resizeColumnsToContents()
        #self.tableWidget_Dex_maplists.resizeRowsToContents()
        pass

    def m_showProcessBar(self, cost: float):
        cur_value = int(cost * 100)
        self.f_widget.progressBar_Dex.setValue(cur_value)
        pass

# class BACK_Thread(QThread):
#     def __init__(self, func, *args, **kwargs):
#         super(BACK_Thread,self).__init__()
#         self.func = func
#         self.args = args
#         self.kwargs = kwargs
#
#
#     def run(self):
#         self.func(*self.args, **self.kwargs)
