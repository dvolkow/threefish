all: smoke_test.cpp ../debug/threefish.hpp
	g++ -std=c++14 -Wall -Wextra -pedantic -Wcast-align -Wcast-qual -Wconversion -Wctor-dtor-privacy -Wdisabled-optimization -Wfloat-equal -Wformat=2 -Winit-self -Wlogical-op -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wundef -Wno-unused -Wno-variadic-macros -Wno-parentheses -fsanitize=address -fsanitize=undefined -fno-sanitize-recover -fstack-protector -fdiagnostics-show-option smoke_test.cpp -o run_test
	./run_test
clang_: smoke_test.cpp ../debug/threefish.hpp
	clang++ -std=c++14 -Wall -Wextra -pedantic -Wcast-align -Wcast-qual -Wconversion -Wctor-dtor-privacy -Wdisabled-optimization -Wfloat-equal -Wformat=2 -Winit-self -Wmissing-include-dirs -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-promo -Wstrict-overflow=5 -Wundef -Wno-unused -Wno-variadic-macros -Wno-parentheses -fsanitize=address -fsanitize=undefined -fstack-protector -fdiagnostics-show-option smoke_test.cpp -o run_test
	./run_test
debug_gcc: smoke_test.cpp ../debug/threefish.hpp
	g++ -std=c++14 -g3 -Wall -Wextra -pedantic -Wcast-align -Wcast-qual -Wconversion -Werror -Wctor-dtor-privacy -Wdisabled-optimization -Wfloat-equal -Wformat=2 -Winit-self -Wlogical-op -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wundef -Wno-unused -Wno-variadic-macros -Wno-parentheses -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC -fsanitize=address -fsanitize=undefined -fno-sanitize-recover -fstack-protector -fdiagnostics-show-option smoke_test.cpp -o run_test
	./run_test
clean:
	rm run_test a.out
