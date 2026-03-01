#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
static_dependency_injector.py - 静态依赖注入模块

将静态分析提取的数据依赖注入到模糊测试的动态数据依赖中。

【推荐】在首次获取动态依赖后注入的使用方式：

在 execution_trace_analysis.py 的 ExecutionTraceAnalyzer 类中：

1. 在 __init__ 中添加标志：
   self._static_injected = False

2. 在分析 SLOAD 或 SSTORE 的代码块后添加：
   
   # 首次获取到动态依赖后，补充静态依赖
   if not self._static_injected and self.env.data_dependencies:
       from static_analysis.static_dependency_injector import inject_static_dependencies_once
       inject_static_dependencies_once(self.env, self.env.runtime_bytecode)
       self._static_injected = True
"""

from typing import Dict, Set
from static_analysis.path import PathAnalyzer


class StaticDependencyInjector:
    """静态依赖注入器"""
    
    def __init__(self, bytecode: str):
        self.bytecode = bytecode
        self._static_deps = None
    
    def get_static_dependencies(self) -> Dict[str, Dict[str, Set[int]]]:
        """获取静态数据依赖"""
        if self._static_deps is None:
            try:
                analyzer = PathAnalyzer(self.bytecode)
                self._static_deps = analyzer.analyze()
            except Exception as e:
                print(f"[StaticDependencyInjector] 静态分析失败: {e}")
                self._static_deps = {}
        return self._static_deps
    
    @staticmethod
    def merge_dependencies(
        dynamic_deps: Dict[str, Dict[str, Set[int]]],
        static_deps: Dict[str, Dict[str, Set[int]]]
    ) -> Dict[str, Dict[str, Set[int]]]:
        """
        合并动态依赖和静态依赖
        
        - 函数签名不存在则添加
        - 已存在则 read/write 分别取并集
        """
        merged = {}
        
        # 复制动态依赖
        for func_sig, dep in dynamic_deps.items():
            merged[func_sig] = {
                "read": set(dep.get("read", set())),
                "write": set(dep.get("write", set()))
            }
        
        # 合并静态依赖
        for func_sig, static_dep in static_deps.items():
            if func_sig not in merged:
                merged[func_sig] = {
                    "read": set(static_dep.get("read", set())),
                    "write": set(static_dep.get("write", set()))
                }
            else:
                merged[func_sig]["read"].update(static_dep.get("read", set()))
                merged[func_sig]["write"].update(static_dep.get("write", set()))
        
        return merged


def inject_static_dependencies_once(env, runtime_bytecode: str, verbose: bool = True) -> None:
    """
    便捷函数：在首次获取动态依赖后注入静态依赖（只调用一次）
    
    Args:
        env: FuzzingEnvironment 实例
        runtime_bytecode: 运行时字节码
        verbose: 是否打印信息
    """
    injector = StaticDependencyInjector(runtime_bytecode)
    static_deps = injector.get_static_dependencies()
    
    if not static_deps:
        if verbose:
            print("[StaticDependencyInjector] 未提取到静态依赖")
        return
    
    if not hasattr(env, 'data_dependencies'):
        env.data_dependencies = {}
    
    # 记录合并前的状态
    old_keys = set(env.data_dependencies.keys())
    
    # 合并
    env.data_dependencies = StaticDependencyInjector.merge_dependencies(
        env.data_dependencies, 
        static_deps
    )
    
    if verbose:
        new_keys = set(env.data_dependencies.keys())
        added_keys = new_keys - old_keys
        merged_keys = old_keys & set(static_deps.keys())
        
        print(f"[StaticDependencyInjector] 静态依赖补充完成:")
        print(f"  - 静态分析提取: {len(static_deps)} 个函数")
        print(f"  - 新增: {len(added_keys)} 个, 合并: {len(merged_keys)} 个")
        
        for sig in sorted(static_deps.keys()):
            slots = sorted(static_deps[sig]['read'])
            tag = "[新增]" if sig in added_keys else "[合并]"
            print(f"    {tag} {sig}: read={slots}")

