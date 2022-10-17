#include "PatternChecker.h"
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace fs = std::filesystem;

struct BadLocation
{
    std::string badName;
    fs::path badLocation;
    fs::path flagLocation;

    BadLocation() = delete;
    BadLocation(std::string badName, fs::path badLocation, fs::path flagLocation);
};

BadLocation::BadLocation(std::string badName, fs::path badLocation, fs::path flagLocation)
    :badName(std::move(badName))
    , badLocation(std::move(badLocation))
    , flagLocation(std::move(flagLocation))
{}

bool EndsWith(const std::string& parent, std::string_view target)
{
    return parent.rfind(target) == (parent.size() - target.size());
}
bool StartsWith(const std::string& parent, std::string_view target)
{
    auto fPos = parent.find(target);
    return fPos == 0;
}

std::optional<std::reference_wrapper<const MatchSet>> 
IsLocationSuspicious(fs::path path, const std::vector<MatchSet>& badSets)
{
    bool pathIsDir = fs::is_directory(path);

    for(const auto& pattern : badSets)
    {
        if (pattern.isDirectory != pathIsDir)
        {
            continue;
        }
        
        if ((pattern.isSuffix && EndsWith(path.generic_string(), pattern.matchString))
            || (!pattern.isSuffix && StartsWith(fs::relative(path, path.parent_path()).generic_string(), pattern.matchString)))
        {
            return std::optional<std::reference_wrapper<const MatchSet>>(std::in_place, pattern);
        }
    }

    return {};
}

std::vector<BadLocation> CheckPatterns(fs::path basePath, 
    const std::vector<MatchSet>& badSets)
{
    std::vector<BadLocation> badLocations;
    for (const auto& thisPath : fs::recursive_directory_iterator(basePath))
    {
        if (auto sus = IsLocationSuspicious(thisPath.path(), badSets); sus.has_value())
        {
            const auto& badPath = thisPath.path();
            fs::path parentLocation = badPath;
            const auto& susRef = sus.value().get();
            if (susRef.reportParent)
            {
                int prntCnt = susRef.parentOffset;
                do
                {
                    parentLocation = parentLocation.parent_path();
                    prntCnt--;
                } while (prntCnt > 0);
            }

            std::string locationName = thisPath.is_directory()
                ? fs::relative(thisPath, badPath.parent_path()).generic_string()
                : badPath.filename().generic_string();

            badLocations.emplace_back(locationName, fs::relative(badPath.parent_path(), basePath),
                fs::relative(parentLocation, basePath));
        }
    }

    return badLocations;
}

void ReportLocations(const std::vector<BadLocation>& badSpots)
{
    for (const auto& bad : badSpots)
    {
        std::cout << "\tYou have " << std::quoted(bad.badName) << " left at location ";
        std::cout << bad.badLocation.generic_string();
        std::cout << std::endl;
        std::cout << "\t - Consider deleting " << bad.flagLocation.generic_string();
        std::cout << std::endl;
    }
}

void CheckAndReportPatterns(std::string_view basePath, const std::vector<MatchSet>& badSets)
{
    auto badSpots = CheckPatterns(basePath, badSets);
    ReportLocations(badSpots);
}

void FixCurrentDirectory(std::string_view correctPath)
{
    std::filesystem::current_path(fs::path{ correctPath }.parent_path());
}
