import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from security.cve_checker import CVEChecker
from security.nvd_cache import load_entries
from security_fixtures import DEVICES, sample_feed


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / 'nvdcve-test.json'
        self.path.write_text(json.dumps(sample_feed(5)), encoding='utf-8-sig')
        self.checker = CVEChecker()
        self.checker.cache_dir = self.root

    def tearDown(self):
        self.temp.cleanup()

    def test_persistent_cache_bypasses_raw_feed_parser(self):
        expected = load_entries(self.path, self.checker._parse_nvd_item)
        parser = Mock(side_effect=AssertionError('Raw feed must not be reparsed'))
        self.assertEqual(load_entries(self.path, parser), expected)
        parser.assert_not_called()
        self.assertTrue(all(not entry['keywords'] for entry in expected))

    def test_source_change_and_truncated_cache_rebuild(self):
        load_entries(self.path, self.checker._parse_nvd_item)
        self.path.write_text(json.dumps(sample_feed(7)), encoding='utf-8')
        self.assertEqual(len(load_entries(self.path, self.checker._parse_nvd_item)), 7)
        derived = self.root / '.parsed-v1' / (self.path.name + '.jsonl')
        derived.write_text(derived.read_text().splitlines()[0] + '\n', encoding='utf-8')
        self.assertEqual(len(load_entries(self.path, self.checker._parse_nvd_item)), 7)
        derived.write_text('[]\n', encoding='utf-8')
        self.assertEqual(len(load_entries(self.path, self.checker._parse_nvd_item)), 7)
        self.path.write_text('broken source', encoding='utf-8')
        with self.assertRaises(ValueError):
            load_entries(self.path, self.checker._parse_nvd_item)

    def test_gzip_and_read_only_cache_fallback(self):
        compressed = self.root / 'nvdcve-test.json.gz'
        with gzip.open(compressed, 'wt', encoding='utf-8-sig') as output:
            json.dump(sample_feed(5), output)
        with patch('security.nvd_cache.tempfile.mkstemp', side_effect=PermissionError('test read-only')):
            self.assertEqual(len(load_entries(compressed, self.checker._parse_nvd_item)), 5)

    def test_query_cache_invalidates_for_completion_inventory_and_feeds(self):
        original = self.checker.search(DEVICES, scope='catalog')
        index = self.checker._search_index
        with patch.object(index, 'search', wraps=index.search) as search:
            self.assertEqual(self.checker.search(DEVICES, scope='catalog'), original)
            search.assert_not_called()
            completed = {original['items'][0]['cve_id']}
            self.assertEqual(self.checker.search(DEVICES, completed, scope='catalog')['total'], 4)
            self.assertEqual(search.call_count, 1)
        self.assertEqual(self.checker.search([], scope='affected')['total'], 0)
        self.path.write_text(json.dumps(sample_feed(7)), encoding='utf-8')
        self.assertEqual(self.checker.search(DEVICES, scope='catalog')['total'], 7)
        self.path.unlink()
        self.assertEqual(self.checker.search(DEVICES, scope='catalog')['total'], 0)

    def test_bounded_result_cache(self):
        for i in range(25):
            self.checker.search(DEVICES, q=f'missing-{i}', scope='catalog')
        self.assertEqual(len(self.checker._result_cache), 16)


if __name__ == '__main__':
    unittest.main()
