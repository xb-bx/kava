MAKEFLAGS += -rR
COLLECTIONS=\
			zip=libs/odin-zip/src\
			kava=src\
			libzip=libs/odin-zip/libzip\
			x86asm=libs/x86asm/src
COLLECTIONS_FLAGS=$(addprefix -collection:, $(COLLECTIONS))

NATIVE=$(shell find src/vm/native -type f | sed '/.generated/d')
GENERATED=$(foreach t,$(NATIVE),$(subst .odin,.generated.odin,$(t)))

ODIN_FLAGS ?=\
		   -o:none \
		   -debug \
		   -thread-count:$(shell nproc) \
		   -use-separate-modules \
		   -error-pos-style:unix
GDB=/opt/gdb11/bin/gdb
ifeq ($(OS), Windows_NT)
	KAVA=bin/kava.exe
	CLASSPARSER=bin/classparser.exe
	NATIVEGENERATOR=bin/native-generator.exe
	JRE_URL=https://builds.openlogic.com/downloadJDK/openlogic-openjdk-jre/8u392-b08/openlogic-openjdk-jre-8u392-b08-windows-x64.zip
else
	KAVA=bin/kava
	CLASSPARSER=bin/classparser
	NATIVEGENERATOR=bin/native-generator
	JRE_URL=https://builds.openlogic.com/downloadJDK/openlogic-openjdk-jre/8u392-b08/openlogic-openjdk-jre-8u392-b08-linux-x64.tar.gz
endif
GDBPLUGIN=bin/gdbplugin.so
JRE=bin/jre


.PHONY: phony
define DEPENDABLE_VAR
$1: phony
	@# 4 dollar-signs in a row to attract money 
	@if [ -f $1 ]; then VALUE=`cat $1`; else touch $1; VALUE=""; fi; \
	if [[ "$$$$VALUE" != '$($1)' ]]; then \
		echo -n '$($1)' > $1; \
	fi
endef

$(eval $(call DEPENDABLE_VAR,BREAKPOINT))
$(eval $(call DEPENDABLE_VAR,ODIN_FLAGS))

all: $(KAVA) $(CLASSPARSER) $(GDBPLUGIN) $(JRE)

$(NATIVEGENERATOR): src/native-generator.odin
	odin build src/native-generator.odin -file -out:$@

src/vm/native/%.generated.odin: src/vm/native/%.odin $(NATIVEGENERATOR)
	./$(NATIVEGENERATOR) $<
src/vm/native/initialize.generated.odin: $(GENERATED) $(NATIVEGENERATOR)
	./$(NATIVEGENERATOR) initializer

libs/odin-zip: 
	mkdir -p libs
	git clone https://github.com/xb-bx/odin-zip $@
	@if [ "$(OS)" = "Windows_NT" ]; then\
		cd libs/odin-zip; ./build.bat;\
	else \
		cd libs/odin-zip; ./build.sh; \
	fi
libs/x86asm:
	mkdir -p libs
	git clone https://github.com/xb-bx/x86asm $@

$(JRE):
	mkdir -p $(JRE)
	wget $(JRE_URL) -O $(JRE)/jre.tar.gz
	@if [ $(OS) = "Windows_NT" ]; then \
		unzip -o $(JRE)/jre.tar.gz -d $(JRE); \
	else \
		tar xvf $(JRE)/jre.tar.gz -C $(JRE); \
	fi
	find $(JRE) -name "*.jar" | xargs -I {} cp {} $(JRE)/
	ls -1a $(JRE)/*.jar | xargs -I {} unzip -o -d $(JRE) {}


RUNTIME_CLASSES=$(shell find src/runtime -type f -name "*.java" | sed "s/.java$$/.class/" | sed "s|src|bin|")
bin/runtime/%.class: src/runtime/%.java $(JRE) 
	@mkdir -p bin/runtime
	javac -sourcepath . -cp $(JRE) $< -d bin/runtime

	
CLASSPARSER_SRC=src/classparser/*.odin src/shared/*.odin
$(CLASSPARSER): $(CLASSPARSER_SRC) ODIN_FLAGS libs/odin-zip libs/x86asm
	@mkdir -p bin
	odin build src/classparser $(COLLECTIONS_FLAGS) $(ODIN_FLAGS) -out:$@

KAVA_SRC=src/kava/*.odin src/vm/*.odin src/vm/native/*.odin src/shared/*.odin

$(KAVA): BREAKPOINT ODIN_FLAGS libs/odin-zip libs/x86asm $(GENERATED) src/vm/native/initialize.generated.odin $(KAVA_SRC) $(CLASSPARSER_SRC) $(RUNTIME_CLASSES)
	@mkdir -p bin
ifdef BREAKPOINT
	odin build src/kava $(COLLECTIONS_FLAGS) $(ODIN_FLAGS) -out:$@ \
		-define:BREAKPOINT_CLASS_NAME='$(shell echo '$(BREAKPOINT)' | cut -d':' -f1)' \
		-define:BREAKPOINT_METHOD_NAME='$(shell echo '$(BREAKPOINT)' | cut -d':' -f2)' \
		-define:BREAKPOINT_METHOD_DESCRIPTOR='$(shell echo '$(BREAKPOINT)' | cut -d':' -f3)'
else
	odin build src/kava $(COLLECTIONS_FLAGS) $(ODIN_FLAGS) -out:$@
endif

$(GDBPLUGIN): ODIN_FLAGS src/gdbplugin/*.odin libs/odin-zip libs/x86asm
	@mkdir -p bin
	odin build src/gdbplugin -build-mode:dynamic -out:$@ $(COLLECTIONS_FLAGS) $(ODIN_FLAGS)

.PHONY: clean
clean:
	rm -f src/vm/native/*.generated.odin
	rm -f $(KAVA) $(CLASSPARSER) $(GDBPLUGIN) $(NATIVEGENERATOR)
	rm -f $(shell find src/runtime -type f -name "*.class")
	rm -rf bin/runtime

.PHONY: distclean
distclean: clean
	rm -rf $(JRE) libs/odin-zip libs/x86asm

testclasses/tictactoe/Main.class: testclasses/tictactoe/Main.java
	javac testclasses/tictactoe/Main.java
testclasses/helloworld/HelloWorld.class: testclasses/helloworld/HelloWorld.java
	javac testclasses/helloworld/HelloWorld.java
.PHONY: run-helloworld
run-helloworld: $(KAVA) testclasses/helloworld/HelloWorld.class
	./$(KAVA) -cp testclasses/helloworld HelloWorld
debug-helloworld: $(KAVA) testclasses/helloworld/HelloWorld.class 
	$(GDB) --args ./$(KAVA) -cp testclasses/helloworld HelloWorld
.PHONY: run-helloworld-java
run-helloworld-java: $(KAVA) testclasses/helloworld/HelloWorld.class
	java -cp testclasses/helloworld HelloWorld

.PHONY: run-tictactoe
run-tictactoe: $(KAVA) testclasses/tictactoe/Main.class
	./$(KAVA) -cp testclasses tictactoe/Main
.PHONY: debug-tictactoe
debug-tictactoe: $(KAVA) testclasses/tictactoe/Main.class
	$(GDB) --args ./$(KAVA) -cp testclasses tictactoe/Main
