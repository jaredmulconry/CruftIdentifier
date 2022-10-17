#include "PatternLoader.h"
#include <algorithm>
#include <charconv>
#include <fstream>
#include <regex>
#include <stdexcept>
#include <utility>

MatchSet::MatchSet(std::string matchString, bool isDirectory, bool reportParent)
    : matchString(std::move(matchString))
    , isDirectory(isDirectory)
    , reportParent(reportParent)
{}

void swap(MatchSet& a, MatchSet& b)
{
    std::swap(a.isDirectory, b.isDirectory);
    std::swap(a.isSuffix, b.isSuffix);
    std::swap(a.reportParent, b.reportParent);
    std::swap(a.parentOffset, b.parentOffset);
    std::swap(a.matchString, b.matchString);
}

std::vector<MatchSet> LoadPatterns(std::string_view path, std::string_view regexString)
{
    std::ifstream sussStrings{ std::string(path) };
    if (!sussStrings.is_open())
    {
        std::string errString = 
"No list of suspicious strings found. \
Provide a file called SuspiciousStrings.txt with \
appropriate patterns to match.";
        throw std::runtime_error{ errString };
    }

    //Matching structure
        //1. Text to match
        //2. d|f - Directory or file
        //3. t[n]|f - Report parent directory. If t, specify a number above 0 for how many parent directories up you wish to report. Default is 1.
        //4 (opt). p|s. Suffix is the default. not relevant if a complete match is desired.
    const std::regex matchingSets{ regexString.begin(), regexString.end(), std::regex_constants::ECMAScript | std::regex_constants::optimize};


    std::vector<MatchSet> suspiciousPatterns;
    while (!sussStrings.eof())
    {
        std::string line;
        std::getline(sussStrings, line);
        std::smatch matchRes;
        if (!std::regex_match(line, matchRes, matchingSets))
        {
            std::string errText = "Invalid Suss Pattern - ";
            errText += line 
+ "\nPattern must be in the following form: \
<text_to_match> <d|f> <t[n{1}]|f> [p|{s}]";
            throw std::runtime_error{ errText };
        }

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

    /*std::stable_partition(suspiciousPatterns.begin(), suspiciousPatterns.end(),
        [](const MatchSet& a)
        {
            return a.isDirectory;
        });*/

    return suspiciousPatterns;
}
