/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     MZN_INTEGER_LITERAL = 258,
     MZN_BOOL_LITERAL = 259,
     MZN_FLOAT_LITERAL = 260,
     MZN_IDENTIFIER = 261,
     MZN_QUOTED_IDENTIFIER = 262,
     MZN_STRING_LITERAL = 263,
     MZN_TI_IDENTIFIER = 264,
     MZN_VAR = 265,
     MZN_PAR = 266,
     MZN_SVAR = 267,
     MZN_ABSENT = 268,
     MZN_ANN = 269,
     MZN_ANNOTATION = 270,
     MZN_ANY = 271,
     MZN_ARRAY = 272,
     MZN_BOOL = 273,
     MZN_CASE = 274,
     MZN_CONSTRAINT = 275,
     MZN_DEFAULT = 276,
     MZN_ELSE = 277,
     MZN_ELSEIF = 278,
     MZN_ENDIF = 279,
     MZN_ENUM = 280,
     MZN_FLOAT = 281,
     MZN_FUNCTION = 282,
     MZN_IF = 283,
     MZN_INCLUDE = 284,
     MZN_INT = 285,
     MZN_LET = 286,
     MZN_LIST = 287,
     MZN_MAXIMIZE = 288,
     MZN_MINIMIZE = 289,
     MZN_OF = 290,
     MZN_OPT = 291,
     MZN_SATISFY = 292,
     MZN_OUTPUT = 293,
     MZN_PREDICATE = 294,
     MZN_RECORD = 295,
     MZN_SET = 296,
     MZN_SOLVE = 297,
     MZN_STRING = 298,
     MZN_TEST = 299,
     MZN_THEN = 300,
     MZN_TUPLE = 301,
     MZN_TYPE = 302,
     MZN_UNDERSCORE = 303,
     MZN_VARIANT_RECORD = 304,
     MZN_WHERE = 305,
     MZN_LEFT_BRACKET = 306,
     MZN_LEFT_2D_BRACKET = 307,
     MZN_RIGHT_BRACKET = 308,
     MZN_RIGHT_2D_BRACKET = 309,
     UNKNOWN_CHAR = 310,
     FLATZINC_IDENTIFIER = 311,
     PREC_ANNO = 312,
     MZN_EQUIV = 313,
     MZN_RIMPL = 314,
     MZN_IMPL = 315,
     MZN_XOR = 316,
     MZN_OR = 317,
     MZN_AND = 318,
     MZN_NQ = 319,
     MZN_EQ = 320,
     MZN_GQ = 321,
     MZN_LQ = 322,
     MZN_GR = 323,
     MZN_LE = 324,
     MZN_SUPERSET = 325,
     MZN_SUBSET = 326,
     MZN_IN = 327,
     MZN_SYMDIFF = 328,
     MZN_DIFF = 329,
     MZN_UNION = 330,
     MZN_DOTDOT = 331,
     MZN_MINUS = 332,
     MZN_PLUS = 333,
     MZN_INTERSECT = 334,
     MZN_MOD = 335,
     MZN_IDIV = 336,
     MZN_DIV = 337,
     MZN_MULT = 338,
     MZN_NOT = 339,
     MZN_PLUSPLUS = 340,
     MZN_COLONCOLON = 341,
     MZN_EQUIV_QUOTED = 342,
     MZN_IMPL_QUOTED = 343,
     MZN_RIMPL_QUOTED = 344,
     MZN_OR_QUOTED = 345,
     MZN_XOR_QUOTED = 346,
     MZN_AND_QUOTED = 347,
     MZN_LE_QUOTED = 348,
     MZN_GR_QUOTED = 349,
     MZN_LQ_QUOTED = 350,
     MZN_GQ_QUOTED = 351,
     MZN_EQ_QUOTED = 352,
     MZN_NQ_QUOTED = 353,
     MZN_IN_QUOTED = 354,
     MZN_SUBSET_QUOTED = 355,
     MZN_SUPERSET_QUOTED = 356,
     MZN_UNION_QUOTED = 357,
     MZN_DIFF_QUOTED = 358,
     MZN_SYMDIFF_QUOTED = 359,
     MZN_DOTDOT_QUOTED = 360,
     MZN_PLUS_QUOTED = 361,
     MZN_MINUS_QUOTED = 362,
     MZN_MULT_QUOTED = 363,
     MZN_DIV_QUOTED = 364,
     MZN_IDIV_QUOTED = 365,
     MZN_MOD_QUOTED = 366,
     MZN_INTERSECT_QUOTED = 367,
     MZN_NOT_QUOTED = 368,
     MZN_COLONCOLON_QUOTED = 369,
     MZN_PLUSPLUS_QUOTED = 370
   };
#endif
/* Tokens.  */
#define MZN_INTEGER_LITERAL 258
#define MZN_BOOL_LITERAL 259
#define MZN_FLOAT_LITERAL 260
#define MZN_IDENTIFIER 261
#define MZN_QUOTED_IDENTIFIER 262
#define MZN_STRING_LITERAL 263
#define MZN_TI_IDENTIFIER 264
#define MZN_VAR 265
#define MZN_PAR 266
#define MZN_SVAR 267
#define MZN_ABSENT 268
#define MZN_ANN 269
#define MZN_ANNOTATION 270
#define MZN_ANY 271
#define MZN_ARRAY 272
#define MZN_BOOL 273
#define MZN_CASE 274
#define MZN_CONSTRAINT 275
#define MZN_DEFAULT 276
#define MZN_ELSE 277
#define MZN_ELSEIF 278
#define MZN_ENDIF 279
#define MZN_ENUM 280
#define MZN_FLOAT 281
#define MZN_FUNCTION 282
#define MZN_IF 283
#define MZN_INCLUDE 284
#define MZN_INT 285
#define MZN_LET 286
#define MZN_LIST 287
#define MZN_MAXIMIZE 288
#define MZN_MINIMIZE 289
#define MZN_OF 290
#define MZN_OPT 291
#define MZN_SATISFY 292
#define MZN_OUTPUT 293
#define MZN_PREDICATE 294
#define MZN_RECORD 295
#define MZN_SET 296
#define MZN_SOLVE 297
#define MZN_STRING 298
#define MZN_TEST 299
#define MZN_THEN 300
#define MZN_TUPLE 301
#define MZN_TYPE 302
#define MZN_UNDERSCORE 303
#define MZN_VARIANT_RECORD 304
#define MZN_WHERE 305
#define MZN_LEFT_BRACKET 306
#define MZN_LEFT_2D_BRACKET 307
#define MZN_RIGHT_BRACKET 308
#define MZN_RIGHT_2D_BRACKET 309
#define UNKNOWN_CHAR 310
#define FLATZINC_IDENTIFIER 311
#define PREC_ANNO 312
#define MZN_EQUIV 313
#define MZN_RIMPL 314
#define MZN_IMPL 315
#define MZN_XOR 316
#define MZN_OR 317
#define MZN_AND 318
#define MZN_NQ 319
#define MZN_EQ 320
#define MZN_GQ 321
#define MZN_LQ 322
#define MZN_GR 323
#define MZN_LE 324
#define MZN_SUPERSET 325
#define MZN_SUBSET 326
#define MZN_IN 327
#define MZN_SYMDIFF 328
#define MZN_DIFF 329
#define MZN_UNION 330
#define MZN_DOTDOT 331
#define MZN_MINUS 332
#define MZN_PLUS 333
#define MZN_INTERSECT 334
#define MZN_MOD 335
#define MZN_IDIV 336
#define MZN_DIV 337
#define MZN_MULT 338
#define MZN_NOT 339
#define MZN_PLUSPLUS 340
#define MZN_COLONCOLON 341
#define MZN_EQUIV_QUOTED 342
#define MZN_IMPL_QUOTED 343
#define MZN_RIMPL_QUOTED 344
#define MZN_OR_QUOTED 345
#define MZN_XOR_QUOTED 346
#define MZN_AND_QUOTED 347
#define MZN_LE_QUOTED 348
#define MZN_GR_QUOTED 349
#define MZN_LQ_QUOTED 350
#define MZN_GQ_QUOTED 351
#define MZN_EQ_QUOTED 352
#define MZN_NQ_QUOTED 353
#define MZN_IN_QUOTED 354
#define MZN_SUBSET_QUOTED 355
#define MZN_SUPERSET_QUOTED 356
#define MZN_UNION_QUOTED 357
#define MZN_DIFF_QUOTED 358
#define MZN_SYMDIFF_QUOTED 359
#define MZN_DOTDOT_QUOTED 360
#define MZN_PLUS_QUOTED 361
#define MZN_MINUS_QUOTED 362
#define MZN_MULT_QUOTED 363
#define MZN_DIV_QUOTED 364
#define MZN_IDIV_QUOTED 365
#define MZN_MOD_QUOTED 366
#define MZN_INTERSECT_QUOTED 367
#define MZN_NOT_QUOTED 368
#define MZN_COLONCOLON_QUOTED 369
#define MZN_PLUSPLUS_QUOTED 370




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE

{ long long int iValue; char* sValue; bool bValue; double dValue;
         MiniZinc::Item* item;
         MiniZinc::VarDecl* vardeclexpr;
         std::vector<MiniZinc::VarDecl*>* vardeclexpr_v;
         MiniZinc::TypeInst* tiexpr;
         std::vector<MiniZinc::TypeInst*>* tiexpr_v;
         MiniZinc::Expression* expression;
         std::vector<MiniZinc::Expression*>* expression_v;
         std::vector<std::vector<MiniZinc::Expression*> >* expression_vv;
         MiniZinc::Generator* generator;
         std::vector<MiniZinc::Generator>* generator_v;
         std::vector<std::string>* string_v;
         std::pair<std::vector<MiniZinc::Expression*>,
                   MiniZinc::Expression*>* expression_p;
         MiniZinc::Generators* generators;
       }
/* Line 1529 of yacc.c.  */

	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



#if ! defined YYLTYPE && ! defined YYLTYPE_IS_DECLARED
typedef struct YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
} YYLTYPE;
# define yyltype YYLTYPE /* obsolescent; will be withdrawn */
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
#endif


