#pragma once
#include <cstring>
#include <memory>
#include <string>
#include <vector>

class TaskList;
class Task {

public:
  Task(std::string const &title, char const *content) : m_title(title) {
    strncpy(m_content, content, 32);
  }

  std::string const &title() const { return m_title; }

  char const *content() const { return m_content; }

private:
  char m_content[32];
  std::string m_title;
};
