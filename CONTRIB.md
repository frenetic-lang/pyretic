=======================
Contribution guidelines
=======================

- First, review Python conventions:
  http://www.python.org/dev/peps/pep-0008/
  http://www.python.org/dev/peps/pep-0257/

  Exceptions:
  - NetCore policies and predicates are written in lowercase. This is because 1)
    they are used often, so the CappedWords are distracting and 2) they aren't
    really used as classes; it is unlikely that one would want to subclass them.

- Second, review Git commit message conventions. Here is a good summary:
  http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html.

- Ideally, commits should add, modify, or remove only one feature. This lets us
  easily revert in the case of regression.
  
