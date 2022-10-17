#include "PatternChecker.h"
#include "PatternLoader.h"
#include <iostream>
#include <vector>

int main(int argc, char** argv)
{
    FixCurrentDirectory(argv[0]);

    if (argc >= 2)
    {
        std::vector<MatchSet> suspiciousPatterns = LoadPatterns("SuspiciousStrings.txt",
            R"(\s*(\S+)\s+(d|f)\s+(f|t)(\d+)?(?:\s*?|\s+(p|s)?)\s*)");

        for (int i = 1; i < argc; i++)
        {
            std::cout << "---Checking directory: " << argv[i] << std::endl;

            CheckAndReportPatterns(argv[i], suspiciousPatterns);
        }
    }
    else
    {
        std::cout << "Usage: Drag the assessment folder(s) onto the executable." << std::endl;
    }
    system("pause");
}