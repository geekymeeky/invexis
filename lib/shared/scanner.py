from abc import ABC, abstractmethod
from urllib3.util.url import Url


class Scanner(ABC):

    def __init__(self, target: Url):
        self.target = target

    @abstractmethod
    def scan(self):
        pass