#include "Task.h"
#include "TaskList.h"
#include <iostream>
#include <unistd.h>
#include <vector>

std::vector<std::unique_ptr<TaskList>> g_task_lists;
std::vector<Task *> g_tasks;

void print_banner() {
  std::cout << "         ,   ,\n"
               "        /////|\n"
               "       ///// |\n"
               "      /////  |\n"
               "     |~~~|   |\n"
               "     |===|   |\n"
               "     | T |   |\n"
               "     | A |   |\n"
               "     | S |   |\n"
               "     | K |  / \n"
               "     | S | /  \n"
               "     |===|/   \n"
               "     '---'    \n";
}

void menu() {
  std::cout << "1. Create task list\n"
               "2. Create task\n"
               "3. Edit task\n"
               "4. Add task to task list\n"
               "5. Remove task from task list\n"
               "6. List task lists\n"
               "7. List tasks\n"
               "8. Use scratchpad\n"
               "9. Exit\n";
}

int main(int argc, char *argv[]) {

  bool used_scratchpad = false;

  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  print_banner();

  uint choice;
  while (1) {
    menu();
    std::cout << "> ";
    std::cin >> choice;
    switch (choice) {
    case 1: {
      std::cout << "Enter task list title: ";
      std::string title;
      std::cin >> title;
      g_task_lists.push_back(std::make_unique<TaskList>(title));
      break;
    }
    case 2: {
      std::cout << "Enter task title: ";
      std::string title;
      std::cin >> title;
      std::cout << "Enter task content: ";
      char content[32];
      std::cin >> content;
      auto *task = new Task(title, content);
      g_tasks.push_back(task);
      break;
    }
    case 3: {
      std::cout << "Enter task index: ";
      uint idx;
      std::cin >> idx;
      if (idx >= g_tasks.size())
        break;
      std::cout << "Enter task content: ";
      read(0, const_cast<char *>(g_tasks[idx]->content()), 32);

      break;
    }
    case 4: {
      std::cout << "Enter task list index: ";
      uint list_idx;
      std::cin >> list_idx;
      if (list_idx >= g_task_lists.size())
        break;
      std::cout << "Enter task index: ";
      uint task_idx;
      std::cin >> task_idx;
      if (task_idx >= g_tasks.size())
        break;
      g_task_lists[list_idx]->add_task(g_tasks[task_idx]);
      break;
    }
    case 5: {
      std::cout << "Enter task list index: ";
      uint list_idx;
      std::cin >> list_idx;
      if (list_idx >= g_task_lists.size())
        break;
      std::cout << "Enter task index: ";
      uint task_idx;
      std::cin >> task_idx;
      if (task_idx >= g_tasks.size())
        break;
      g_task_lists[list_idx]->remove_task(task_idx);
      break;
    }
    case 6: {
      for (uint i = 0; i < g_task_lists.size(); ++i) {
        std::cout << i << " - " << g_task_lists[i]->title() << "\n";
        g_task_lists[i]->for_each_task(
            [](size_t i, std::shared_ptr<Task> &task) {
              std::cout << "  " << i << " - " << task->title() << "\n";
            });
      }
      break;
    }
    case 7: {
      std::cout << "Enter task list index: ";
      uint list_idx;
      std::cin >> list_idx;
      if (list_idx >= g_task_lists.size())
        break;

      g_task_lists[list_idx]->for_each_task(
          [](size_t i, std::shared_ptr<Task> &task) {
            std::cout << i << " - " << g_tasks[i]->title() << "\n";
            std::cout << "  > " << g_tasks[i]->content() << "\n";
          });

      break;
    }
    case 8: {
      if (used_scratchpad) {
        std::cout << "You already used the scratchpad!\n";
        break;
      }

      used_scratchpad = true;
      std::cout << "> ";
      char *buffer = new char[0xc00];
      read(0, buffer, 0xc00);
      delete[] buffer;
      break;
    }
    case 9: {
      return 0;
    }
    default:
      break;
    }
  }
}
