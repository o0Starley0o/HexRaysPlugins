# HexRaysPlugins

# **IDAPython Wiki**
## Введение
В данном вики будет описан плагин для поиска имен функций с помощью логирующих функций.
## Цели плагина
1. Разобраться в IDAPython API.
2. ...


## Зависимости
* IDAPython API
## Документация

### Основные функции для работы с API:
 
![alt-текст](https://github.com/inforion/idapython-cheatsheet/releases/download/v1.0/IDAPython_cheatsheet_print_ru.png "Основные возможности API")

* **ScreenEA()** - получить текущую позицию курсора.
* **BeginEA()** - точка входа в программу.
* **NextHead(addr)** - перейти головкой на следующий распознанный элемент.
* **Segments()** - вернуть массив всех адресов сегментов.
* **SegName(seg_ea)** - вернуть имя сегмента по адресу.
* **SegStart(seg_ea)** - стартовый адрес сегмента, в котором лежит адрес.
* **SegEnd(seg_ea)** - конечный адрес сегмента, в котором лежит адрес.

----

* **idc.isCode(GetFlags(addr))** - проверка, является ли элемент по адресу кодом.
* **idc.isData(GetFlags(addr))** - проверка, является ли элемент по адресу данными.
* **idc.isUnknown(GetFlags(addr))** - проверка, является ли элемент по адресу нераспознанным.
* **idc.MakeUnknown(ea,20,idc.DOUNK_SIMPLE)** - сделать следующие 20 байт нераспознанными.
* **idc.MakeCode(ea)** - пометить команду как код.
 
----

* **GetDisasm(addr)** - получить дизассемблированное представление команды по адресу.
* **idc.GetMnem(addr)** - получить мнемонику инструкции по адресу.
* **idc.GetOpType(adr,0)** - получить тип операнда по адресу.  
_Типы операндов: 'idaapi.o_far','idaapi.o_imm','idaapi.o_mem','idaapi.o_near','idaapi.o_reg'._
* **idc.GetOperandValue(adr,0)** - получить значение операнда.  

----

* **XrefsFrom(addr, idaapi.XREF_FAR)** - массив всех переходов из команды с данным адресом.
* **Functions(start_ea,end_ea)** - адреса всех функций.
###Отладочные функции:

* **idc.GetRegValue(name)** - получить значение регистра name.
* **idc.GetDebuggerEvent()** - узнать причину остановки программы.
* **idc.AddBpt(ea)** - установить брейкпоинт на определенный адрес.
* **idc.AddBptEx(ea, size, bpttype)** - установить брейкпоинт по адресу ea типа bpttype.
* bpttype:   
**BPT_EXEC**  _// Hardware: Execute instruction_  
**BPT_WRITE**   _// Hardware: Write access_  
**BPT_RDWR**   _// Hardware: Read/write access_  
**BPT_SOFT**   _// Software breakpoint_  
* **MakeComm(ea, "Text")** - установить комментарий к коду.
* **GetCommentEx(ea,0)** -  получить строчку комментария.
* **idc.SetColor(ea,1,0xa0F0F0)** - установить цвет по адресу ea.  

```
#!python

class DbgHook(DBG_Hooks):
	# Обработчик события, срабатывающий при запуске процесса
	def dbg_process_start(self, pid, tid, ea, name, base, size):
		return

	# Обработчик события, срабатывающий при завершении процесса 
	def dbg_process_exit(self, pid, tid, ea, code):
		return

	# Обработчик события, срабатывающий при загрузке библиотеки
	def dbg_library_load(self, pid, tid, ea, name, base, size):
		return

	# Обработчик срабатывающий при срабатывании точки останова
	def dbg_bpt(self, tid, ea):
		return
```
###Трассировка:
* **RunTo(BeginEA())**  
_event_ = GetDebuggerEvent(WFNE_SUSP, -1)
   
* **EnableTracing(TRACE_STEP, 1)**  
_event_ = GetDebuggerEvent(WFNE_ANY|WFNE_CONT, -1)


```
#!python

for i in range(1000):
  event = GetDebuggerEvent(WFNE_ANY, -1)
  addr = GetEventEa()
  print "Debug: current address", hex(addr), "| debug event", hex(event)
  if event <= 1: break
```
###Новый сегмент:

```
#!python

import idaapi

segaddr = 0x100000
code = [
    "mov eax, 1",
    "xor ebx, ebx",
    "push eax",
    ]

# Создаем новый сегмент
print SegCreate(segaddr, segaddr+0x1000, 0, 1, 0, 0)
print SegRename(segaddr, ".myseg")
# Патчим построчно инструкции
ea = segaddr
for line in code:
    idaapi.assemble(ea, 0, 0, True, line)
    ea += MakeCode(ea)
```


# Примеры



```
#!python

from idaapi import GraphViewer

class MyGraph(GraphViewer):
	def __init__(self, title):
		GraphViewer.__init__(self, title)
	def OnRefresh(self):
		self.Clear()
		self.AddNode(text)
		self.AddEdge(node1,node2)
	def OnGetText(self, node_id):
		return str(self[node_id])

	def OnCommand(self, cmd_id):
		"""
		Triggered when a menu command is selected through the menu or its hotkey
		@return: None
		"""
		if self.cmd_close == cmd_id:
			self.Close()
			return
	def Show(self):
		if not GraphViewer.Show(self):
			return False
		self.cmd_close = self.AddCommand("Close", "F2")
		if self.cmd_close == 0:
			print "Failed to add popup menu item!"
		return True
```


# Ссылки
* Вспомогательные материалы:
	1. [Шпаргалка с основными функциями](https://github.com/inforion/idapython-cheatsheet)

* Для чтения:
	1. [The Beginner's Guide to IDAPython](https://leanpub.com/IDAPython-Book)
