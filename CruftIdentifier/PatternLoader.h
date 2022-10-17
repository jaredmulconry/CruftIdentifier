#pragma once
#include <string>
#include <string_view>
#include <vector>

struct MatchSet
{
    std::string matchString;
    int parentOffset = 1;
    bool isDirectory;
    bool reportParent;
    bool isSuffix = true;

    MatchSet() = delete;
    MatchSet(MatchSet&&) = default;
    MatchSet(std::string matchString, bool isDirectory, bool reportParent);
    MatchSet& operator=(MatchSet&&) = default;


    friend void swap(MatchSet& a, MatchSet& b);
};

std::vector<MatchSet> LoadPatterns(std::string_view path, std::string_view regex);