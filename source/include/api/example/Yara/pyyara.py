import yara
import os
from Utils import config_loader, logger, utils
from DBConnector import db
from DBConnector.tables import YaraRule, YaraEXEResult
import time
import os
logger = logger.Log().get_log()

PATH = os.path.dirname(os.path.realpath(__file__))
YARA_RULE_PATH = os.path.join(PATH, "rules")


class Yara(metaclass=utils.Singleton):

    def __init__(self):
        self.rule_path = YARA_RULE_PATH
        self.rules = self.compile()
        self.data = set()
        self.db = db.DBService()

    # 获取目录内的yara规则文件
    # 将yara规则编译
    def compile(self):
        filepaths = {}
        start = time.time()
        self.get_rule_path(filepaths, self.rule_path)
        rules = yara.compile(filepaths=filepaths)
        logger.info(f"Compile yara rules cost {time.time() - start:.4f}")
        return rules

    @staticmethod
    def get_rule_path(dict_filepath: dict, path):
        for index, p in enumerate(os.listdir(path)):
            curr_path = os.path.join(path, p)
            # if os.path.isdir(curr_path):
            #     self.get_rule_path(dict_filepath, curr_path)
            if p.endswith("yar"):
                key = f"{path.split('/')[-1]}_rule_{index}"
                dict_filepath[key] = curr_path

    def scan(self, filepath):
        rule_set = set()

        def callback(data):
            if not self.db.is_rule_exist(data['rule']):
                _rule = YaraRule(data['rule'])
                meta = data['meta']
                if 'author' in meta:
                    _rule.author = meta['author']
                if 'Author' in meta:
                    _rule.author = meta['Author']
                if 'description' in meta:
                    _rule.description = meta['description']
                if 'Description' in meta:
                    _rule.description = meta['Description']
                if 'date' in meta:
                    _rule.date = (meta['date'] + "-01")[:10]
                if 'Date' in meta:
                    _rule.date = (meta['Date'] + "-01")[:10]
                if 'reference' in meta:
                    _rule.reference = meta['reference']
                if 'Reference' in meta:
                    _rule.reference = meta['Reference']
                self.db.save_item(_rule)
            rule_set.add(data['rule'])
            return yara.CALLBACK_CONTINUE

        self.rules.match(filepath, callback=callback,
                         which_callbacks=yara.CALLBACK_MATCHES)
        rules = []
        for rule in rule_set:
            rules.append(YaraEXEResult(rule=rule, md5=os.path.basename(filepath)))
        logger.info(f"{filepath} match rules of {rule_set}")
        self.db.save_items(rules)





