#pragma once
#include "Task.h"
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

class TaskList {

public:
  TaskList(std::string const &title) : m_title(title) {}

  void add_task(Task *task) {

    auto ptr = std::shared_ptr<Task>(task);
    m_tasks.push_back(ptr);
  }

  void remove_task(unsigned int idx) {
    if (idx >= m_tasks.size())
      return;
    auto &task = m_tasks[idx];

    m_tasks.erase(m_tasks.begin() + idx);
  }

  template <typename Callback> void for_each_task(Callback cb) {
    for (size_t i = 0; i < m_tasks.size(); ++i) {
      cb(i, m_tasks[i]);
    }
  }

  std::string const &title() const { return m_title; }

private:
  std::string m_title;
  std::vector<std::shared_ptr<Task>> m_tasks;
};
