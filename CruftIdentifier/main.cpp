#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include <charconv>
#include <codecvt>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

struct MatchSet
{
    std::string matchString;
    int parentOffset = 1;
    bool isDirectory;
    bool reportParent;
    bool isSuffix = true;

    MatchSet() = delete;
    MatchSet(std::string matchString, bool isDirectory, bool reportParent)
        : matchString(std::move(matchString))
        , isDirectory(isDirectory)
        , reportParent(reportParent)
    {}
};

std::vector<MatchSet> suspiciousPatterns;

bool EndsWith(std::filesystem::path parent, std::string_view target)
{
    const auto& nativeParent = parent.native();
    auto cvtTarget = std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t>().from_bytes(target.data(), target.data() + target.size());
    return nativeParent.rfind(cvtTarget) == (nativeParent.size() - cvtTarget.size());
}
bool EndsWith(std::filesystem::path parent, std::wstring_view target)
{
    const auto& nativeParent = parent.native();
    return nativeParent.rfind(target) == (nativeParent.size() - target.size());
}

std::optional<MatchSet> IsStringSuspicious(std::filesystem::path path)
{
    for (int i = 0; i < suspiciousPatterns.size(); i++)
    {
        if (EndsWith(path, suspiciousPatterns[i].matchString))
        {
            return suspiciousPatterns[i];
        }
    }

    return {};
}

struct BadLocation
{
    std::string badName;
    std::filesystem::path badLocation;
    std::filesystem::path flagLocation;

    BadLocation() = delete;
    BadLocation(std::string badName, std::filesystem::path badLocation, std::filesystem::path flagLocation)
        :badName(std::move(badName))
        ,badLocation(std::move(badLocation))
        ,flagLocation(std::move(flagLocation))
    {}
};

std::vector<BadLocation> CheckFolder(std::filesystem::path basePath)
{
    std::vector<BadLocation> badLocations;
    for (const auto& thisPath : std::filesystem::recursive_directory_iterator(basePath))
    {
        if (auto sus = IsStringSuspicious(thisPath.path()); sus.has_value())
        {
            const auto& badPath = thisPath.path();
            std::filesystem::path parentLocation = badPath;
            const auto& susRef = sus.value();
            if (susRef.reportParent)
            {
                int prntCnt = susRef.parentOffset;
                do
                {
                    parentLocation = parentLocation.parent_path();
                    prntCnt--;
                } while (prntCnt >= 0);
            }

            std::string locationName = thisPath.is_directory()
                ? std::filesystem::relative(thisPath, badPath.parent_path()).generic_string()
                : badPath.filename().generic_string();

            badLocations.emplace_back(locationName, std::filesystem::relative(badPath, basePath),
                std::filesystem::relative(parentLocation, basePath));
            //std::cout << "Perhaps you should delete: " << std::filesystem::relative(thisPath, basePath).generic_string() << std::endl;
        }
    }

    return badLocations;
}

int main(int argc, char** argv)
{
    std::cout << std::string(117, 'a') << '\t' << "ss" << '\n' << "Stuff";

    std::filesystem::path tmpPath = argv[0];
    std::filesystem::current_path(tmpPath.parent_path());

    if (argc >= 2)
    {
        std::ifstream sussStrings("SuspiciousStrings.txt");
        if (!sussStrings.is_open())
        {
            std::cout << "No list of suspicious strings found in location" << std::endl
                << std::filesystem::current_path().generic_string()
                << std::endl <<
                "Provide a file called SuspiciousStrings.txt with " <<
                "text to match at the end of director paths to flag." << std::endl;
            system("pause");
            return 5;
        }
        //Matching structure
        //1. Text to match
        //2. d|f - Directory or file
        //3. t[n]|f - Report parent directory. If t, specify a number above 0 for how many parent directories up you wish to report. Default is 1.
        //4 (opt). p|s. Suffix is the default. not relevant if a complete match is desired.
        std::regex matchingSets{ R"(^\s*(\S+)\s+(d|f)\s+(f|t)(\d+)?(?:\s*?|\s+(p|s)?)\s*$)", std::regex_constants::ECMAScript | std::regex_constants::optimize };

        system("pause");

        while (!sussStrings.eof())
        {
            std::string line;
            std::getline(sussStrings, line);
            std::smatch matchRes;
            if (!std::regex_search(line, matchRes, matchingSets))
            {
                std::cerr << "Invalid Suss Pattern - " << line << '\n';
                std::cerr << "Pattern must be in the following form: <text_to_match> <d|f> <t[n{1}]|f> [p|{s}]" << std::endl;
                continue;
            }

            std::cout << "Rule matched: " << line <<  std::endl;

            MatchSet newSet{ matchRes[1], *matchRes[2].first == 'd', *matchRes[3].first == 't' };

            const auto& directorySmatch = matchRes[4];
            if (directorySmatch.matched)
            {
                int prnOffset = 0;
                auto convRes = std::from_chars(&*directorySmatch.first, &*directorySmatch.first + directorySmatch.length(), prnOffset);
                if (convRes.ec == std::errc::invalid_argument)
                {
                    newSet.parentOffset = prnOffset;
                }
            }
            const auto& posSmatch = matchRes[5];
            if (posSmatch.matched)
            {
                newSet.isSuffix = *posSmatch.first == 's';
            }
            
            //matchRes
            suspiciousPatterns.push_back(std::move(newSet));
        }
        sussStrings.close();

        for (int i = 1; i < argc; i++)
        {
            std::vector<BadLocation> badSpots;
            std::cout << "---Checking directory: " << argv[i] << std::endl;

            badSpots = CheckFolder(std::filesystem::path{ argv[i] });

            auto badText = "CruftIdentifier\\x64\\Debug\\CruftIdentifier.tlog\\CL.write.1.tlog";

            for (const auto& bad : badSpots)
            {
                std::cout << "\tYou have " << std::quoted(bad.badName + "  ") << " left at location ";
                std::cout << bad.badLocation/*.generic_string()*/;
                std::cout << std::endl;
                std::cout << "\t - Consider deleting " << bad.flagLocation.generic_string();
                std::cout <<  std::endl;
            }
        }
    }
    else
    {
        std::cout << "Useage: Drag the assessment folder(s) onto the executable." << std::endl;
    }
    system("pause");
}